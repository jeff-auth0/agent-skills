"""The baseline: a copy of what the generator last produced, stored in the project.

Resync needs three versions of every file to tell a tenant change from a customer
edit:

    baseline  what the generator produced last time   (.auth0tf/baseline/)
    tenant    what the generator produces now
    project   what is on disk, possibly edited by the customer

`transform` writes the baseline; `resync` reads it and refreshes it. It lives in
the project (and is committed with it), so resync never depends on git history.

Only the paths resync owns are stored: modules/, envs/<active env>/ and README.md.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

STATE_DIR = ".auth0tf"
BASELINE_DIR = f"{STATE_DIR}/baseline"
STATE_FILE = f"{STATE_DIR}/state.json"
STATE_VERSION = 1


class NoBaselineError(Exception):
    """The project has no baseline, so a three-way merge is impossible."""


def managed_prefixes(env: str) -> tuple[str, ...]:
    """Paths resync is allowed to touch. Everything else is the customer's."""
    return ("modules/", f"envs/{env}/", "README.md")


def is_managed(rel: str, env: str) -> bool:
    return any(rel == p or rel.startswith(p) for p in managed_prefixes(env))


def collect_managed(root: Path, env: str) -> dict[str, str]:
    """Managed files under a freshly generated tree: relative path -> text.

    Only use this on generator output or on the baseline, never on a customer
    project: a project's envs/<env>/ may hold a .terraform/ cache.
    """
    root = Path(root)
    out: dict[str, str] = {}
    for f in sorted(root.rglob("*")):
        if f.is_file():
            rel = f.relative_to(root).as_posix()
            if is_managed(rel, env):
                out[rel] = f.read_text(encoding="utf-8")
    return out


def write_baseline(project: Path, generated: Path, env: str,
                   other_envs: list[str], secret_keys: list[str]) -> None:
    """Snapshot the generator's managed output plus the facts resync needs."""
    project = Path(project)
    base = project / BASELINE_DIR
    if base.exists():
        shutil.rmtree(base)
    for rel, text in collect_managed(generated, env).items():
        dest = base / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
    state = {
        "version": STATE_VERSION,
        "env": env,
        "other_envs": list(other_envs),     # needed to regenerate an identical README
        "secret_keys": sorted(secret_keys),  # to report newly required secrets
    }
    (project / STATE_FILE).write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")


def read_state(project: Path) -> dict:
    p = Path(project) / STATE_FILE
    if not p.exists():
        raise NoBaselineError(
            f"{p} not found. This project has no baseline (it was generated before "
            "resync existed, or .auth0tf/ was deleted). Re-export it with `transform` "
            "to create one.")
    return json.loads(p.read_text(encoding="utf-8"))


def read_baseline(project: Path, env: str) -> dict[str, str]:
    base = Path(project) / BASELINE_DIR
    if not base.is_dir():
        raise NoBaselineError(f"{base} not found. Re-export the project with `transform`.")
    return collect_managed(base, env)
