"""Resync an existing project with the current state of the Auth0 tenant.

Someone changed the tenant in the dashboard; pull exactly those changes into the
project and leave the customer's own edits alone.

Every managed file is merged three ways (see baseline.py):

    baseline  what the generator produced last time
    tenant    what it produces now
    project   what is on disk

  baseline == tenant                 nothing changed in the tenant: leave the file
  baseline != tenant, project == baseline   take the tenant version
  baseline != tenant, project edited        `git merge-file`: clean merge, or markers
  file only in tenant / only in baseline    add / delete (with safeguards)

Only modules/, envs/<active env>/ and README.md are touched. Other environments,
.gitignore, backend.tf edits, PROJECT_CONTEXT.md and any file the customer added are
never written. Nothing is ever pushed.

Output of the generator must be byte-stable for an unchanged tenant, otherwise every
run would look like a rewrite (tests/test_cli_integration.py guards this).
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import hcl2

from .baseline import (
    BASELINE_DIR,
    STATE_DIR,
    collect_managed,
    is_managed,
    read_baseline,
    read_state,
    write_baseline,
)


class ResyncError(Exception):
    """A precondition failed; nothing was changed."""


@dataclass
class ResyncResult:
    # --- files ---------------------------------------------------------------
    added: list[str] = field(default_factory=list)       # new in tenant, written
    updated: list[str] = field(default_factory=list)     # tenant change, project untouched by customer
    merged: list[str] = field(default_factory=list)      # tenant change merged with customer edits
    deleted: list[str] = field(default_factory=list)     # removed from tenant, deleted
    conflicts: list[str] = field(default_factory=list)   # markers written (or file kept): resolve by hand
    unchanged: list[str] = field(default_factory=list)
    # --- resources (what changed in the tenant) ---------------------------------
    res_added: list[str] = field(default_factory=list)
    res_changed: list[str] = field(default_factory=list)
    res_removed: list[str] = field(default_factory=list)
    # --- secrets ---------------------------------------------------------------
    secrets_new: list[str] = field(default_factory=list)
    secrets_gone: list[str] = field(default_factory=list)
    # --- bookkeeping -------------------------------------------------------------
    branch: str | None = None
    commit: str | None = None
    dry_run: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.added or self.updated or self.merged or self.deleted
                    or self.conflicts)


# ------------------------------------------------------------------------- git

def _git(project: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(["git", *args], cwd=project, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise ResyncError(f"git {' '.join(args)} failed: {r.stderr.strip() or r.stdout.strip()}")
    return r


def _is_git_repo(project: Path) -> bool:
    r = _git(project, "rev-parse", "--is-inside-work-tree", check=False)
    return r.returncode == 0 and r.stdout.strip() == "true"


def _merge(project_text: str, base_text: str, tenant_text: str) -> tuple[str, int]:
    """Three-way merge with `git merge-file`. Returns (text, conflict count)."""
    with tempfile.TemporaryDirectory(prefix="auth0tf-merge-") as d:
        cur, base, other = Path(d, "project"), Path(d, "baseline"), Path(d, "tenant")
        cur.write_text(project_text, encoding="utf-8")
        base.write_text(base_text, encoding="utf-8")
        other.write_text(tenant_text, encoding="utf-8")
        r = subprocess.run(
            ["git", "merge-file", "-p", "-L", "project", "-L", "baseline", "-L", "tenant",
             str(cur), str(base), str(other)],
            capture_output=True, text=True)
    if r.returncode < 0 or r.returncode >= 128:     # error, not a conflict count
        raise ResyncError(f"git merge-file failed: {r.stderr.strip()}")
    return r.stdout, r.returncode


# ----------------------------------------------------------- resource-level report

_LITERAL_RESOURCE_RE = re.compile(r'^resource "(auth0_\w+)" "(\w+)"', re.M)


def _tfvars_resources(text: str) -> dict[str, object]:
    """'variable.resource_key' -> parsed value, from a terraform.tfvars."""
    if not text.strip() or text.lstrip().startswith("# TODO"):
        return {}
    doc = hcl2.loads(text)
    out: dict[str, object] = {}
    for var, val in doc.items():
        if isinstance(val, list) and len(val) == 1:
            val = val[0]
        if isinstance(val, dict):
            for key, body in val.items():
                out[f"{var}.{key.strip(chr(34))}"] = body
        else:
            out[var] = val
    return out


def _literal_resources(files: dict[str, str]) -> set[str]:
    """Resources emitted as named literal blocks (forms, flows, client grants)."""
    found: set[str] = set()
    for rel, text in files.items():
        if rel.startswith("modules/") and rel.endswith(".tf"):
            for tf_type, key in _LITERAL_RESOURCE_RE.findall(text):
                if key != "this":
                    found.add(f"{tf_type}.{key}")
    return found


def _diff_resources(base: dict[str, str], tenant: dict[str, str], env: str,
                    result: ResyncResult) -> None:
    tf = f"envs/{env}/terraform.tfvars"
    b = _tfvars_resources(base.get(tf, ""))
    t = _tfvars_resources(tenant.get(tf, ""))
    for key in sorted(t.keys() - b.keys()):
        result.res_added.append(key)
    for key in sorted(b.keys() - t.keys()):
        result.res_removed.append(key)
    for key in sorted(b.keys() & t.keys()):
        if b[key] != t[key]:
            result.res_changed.append(key)
    bl, tl = _literal_resources(base), _literal_resources(tenant)
    result.res_added += sorted(tl - bl)
    result.res_removed += sorted(bl - tl)
    # literal blocks: a changed body shows up as a changed file, which is reported
    # under files; resource-level "changed" is only tracked for tfvars-driven types.


# ------------------------------------------------------------------------- core

def _plan(base: dict[str, str], tenant: dict[str, str], project: Path,
          env: str) -> tuple[ResyncResult, dict[str, str | None]]:
    """Decide what to do with every managed file. Writes nothing.

    Returns the result and {relative path: new content, or None to delete}.
    """
    res = ResyncResult()
    writes: dict[str, str | None] = {}

    for rel in sorted(base.keys() | tenant.keys()):
        b, t = base.get(rel), tenant.get(rel)
        path = project / rel
        p = path.read_text(encoding="utf-8") if path.is_file() else None

        if b == t:                                   # tenant side unchanged
            res.unchanged.append(rel)
            continue
        if b is None:                                # new in the tenant
            if p is None:
                res.added.append(rel); writes[rel] = t
            elif p == t:
                res.unchanged.append(rel)
            else:                                    # customer made a file with this name
                res.conflicts.append(f"{rel}  (new in tenant, but a different file exists)")
            continue
        if t is None:                                # removed from the tenant
            if p is None:
                res.unchanged.append(rel)            # already gone
            elif p == b:
                res.deleted.append(rel); writes[rel] = None
            else:
                res.conflicts.append(f"{rel}  (removed from tenant, but edited locally: kept)")
            continue
        # changed in the tenant
        if p is None:
            res.conflicts.append(f"{rel}  (changed in tenant, but deleted locally: left deleted)")
        elif p == t:
            res.unchanged.append(rel)
        elif p == b:
            res.updated.append(rel); writes[rel] = t
        else:
            text, n = _merge(p, b, t)
            if n == 0:
                res.merged.append(rel)
            else:
                res.conflicts.append(f"{rel}  ({n} conflict{'s' if n != 1 else ''}: markers written)")
            writes[rel] = text
    return res, writes


def resync(fresh_dir: str | Path, fresh_secret_keys: list[str], project_dir: str | Path,
           env: str, dry_run: bool = False, no_git: bool = False,
           branch: str | None = None) -> ResyncResult:
    """Merge freshly generated output (`fresh_dir`) into `project_dir`.

    `fresh_dir` is a complete generator output for the same environment name and the
    same list of other environments as the original export.
    """
    project = Path(project_dir).expanduser().resolve()
    fresh = Path(fresh_dir).expanduser().resolve()
    if not (project / "modules").is_dir() or not (project / "envs").is_dir():
        raise ResyncError(f"{project} does not look like a generated project "
                          "(modules/ and envs/ are required).")
    if not (project / "envs" / env).is_dir():
        raise ResyncError(f"envs/{env} does not exist in {project}.")

    state = read_state(project)                      # raises NoBaselineError
    if state.get("env") != env:
        raise ResyncError(f"This project was exported for env '{state.get('env')}', "
                          f"not '{env}'. Resync only updates that environment.")
    base = read_baseline(project, env)
    tenant = collect_managed(fresh, env)

    res, writes = _plan(base, tenant, project, env)
    res.dry_run = dry_run
    _diff_resources(base, tenant, env, res)
    old, new = set(state.get("secret_keys", [])), set(fresh_secret_keys)
    res.secrets_new, res.secrets_gone = sorted(new - old), sorted(old - new)

    in_git = _is_git_repo(project)
    if not in_git and not no_git and not dry_run:
        raise ResyncError(f"{project} is not a git repository. Resync works on a branch so "
                          "you can review the result; run `git init` and commit first, or "
                          "pass --no-git to write the changes in place.")
    if dry_run or not (res.changed or res.secrets_new or res.secrets_gone):
        return res                                   # nothing to write

    if in_git and not no_git:
        touched = [p.rstrip("/") for p in
                   (*[f"envs/{env}", "modules", "README.md"], STATE_DIR)]
        dirty = _git(project, "status", "--porcelain", "--", *touched).stdout.strip()
        if dirty:
            lines = dirty.splitlines()
            shown = "\n".join(f"    {ln}" for ln in lines[:8])
            more = f"\n    ... and {len(lines) - 8} more" if len(lines) > 8 else ""
            raise ResyncError("Uncommitted changes in files resync manages. Commit or stash "
                              f"them first ({len(lines)} files):\n{shown}{more}")
        res.branch = _new_branch(project, branch)

    for rel, text in writes.items():
        dest = project / rel
        if text is None:
            dest.unlink(missing_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
    write_baseline(project, fresh, env, state.get("other_envs", []), fresh_secret_keys)

    if in_git and not no_git:
        _git(project, "add", "--", "modules", f"envs/{env}", "README.md", STATE_DIR)
        msg = _commit_message(res)
        _git(project, "commit", "-q", "-m", msg)
        res.commit = _git(project, "rev-parse", "--short", "HEAD").stdout.strip()
    return res


def _new_branch(project: Path, name: str | None) -> str:
    name = name or "auth0/resync"
    candidate, n = name, 2
    while _git(project, "rev-parse", "--verify", "-q", candidate, check=False).returncode == 0:
        candidate, n = f"{name}-{n}", n + 1
    _git(project, "checkout", "-q", "-b", candidate)
    return candidate


def _commit_message(res: ResyncResult) -> str:
    files = (f"Added: {len(res.added)}  Updated: {len(res.updated)}  "
             f"Merged: {len(res.merged)}  Deleted: {len(res.deleted)}  "
             f"Conflicts: {len(res.conflicts)}")
    return (f"auth0-resync: pull tenant changes\n\n{files}\n"
            f"Resources: +{len(res.res_added)} ~{len(res.res_changed)} -{len(res.res_removed)}")


def format_report(res: ResyncResult, env: str) -> str:
    """Human-readable summary printed by the CLI."""
    lines = [f"{'[DRY RUN] ' if res.dry_run else ''}Resync of env '{env}'", ""]
    if not (res.changed or res.secrets_new or res.secrets_gone):
        lines.append("No changes: the tenant matches the project baseline.")
        return "\n".join(lines)

    lines.append("Tenant changes")
    for key in res.res_added:
        lines.append(f"  + added    {key}")
    for key in res.res_changed:
        lines.append(f"  ~ changed  {key}")
    for key in res.res_removed:
        lines.append(f"  - removed  {key}")
    if not (res.res_added or res.res_changed or res.res_removed):
        lines.append("  (no resource-level changes; see files below)")

    if res.res_removed:
        lines += ["", "  WARNING: removed resources. Applying this to a tenant that has them "
                      "will DESTROY them.",
                  "  If a resource was only renamed, the rename shows as a removal plus an addition."]
    if res.secrets_new:
        lines += ["", "New secret keys required (add them to `secrets`, or `plan` will fail):"]
        lines += [f"  + {k}" for k in res.secrets_new]
    if res.secrets_gone:
        lines += ["", "Secret keys no longer required:"]
        lines += [f"  - {k}" for k in res.secrets_gone]

    lines += ["", "Files",
              f"  added {len(res.added)}, updated {len(res.updated)}, merged {len(res.merged)}, "
              f"deleted {len(res.deleted)}, unchanged {len(res.unchanged)}, "
              f"conflicts {len(res.conflicts)}"]
    for label, items in (("added", res.added), ("updated", res.updated),
                         ("merged with your edits", res.merged), ("deleted", res.deleted)):
        for f in items:
            lines.append(f"  {label}: {f}")
    if res.conflicts:
        lines += ["", "CONFLICTS (resolve by hand; files with markers fail `terraform validate`):"]
        lines += [f"  ! {c}" for c in res.conflicts]
    if res.branch:
        lines += ["", f"Committed on branch {res.branch} ({res.commit}). Nothing was pushed.",
                  f"Review with: git diff {res.branch}~1 {res.branch}"]
    elif not res.dry_run:
        lines += ["", "Changes were written in place (--no-git)."]
    return "\n".join(lines)
