"""Extract inline JS (action code) and form/flow JSON bodies to files, replacing
inline values with file() references. Connection `custom_scripts` (DB connection
JS) are HCL-unescaped in place rather than extracted to files: their script-name
keys vary per connection instance, and emit_modules' dynamic-block renderer
builds each block's shape from a single sample instance, so it cannot represent
a per-instance-varying-key map for a single for_each resource. Do not "fix" this
back into file-extraction without also reworking emit_modules/emit_env for that
shape.
"""
from __future__ import annotations

import json as _json
import re
from pathlib import Path

from .hclstr import hcl_unescape as _hcl_unescape
from .model import Tenant

# Body fields in auth0_form / auth0_flow that hold JSON strings after
# _eval_jsonencode processing. Extracted to files so tfvars stays lean.
_FORM_BODY_FIELDS = ("nodes", "ending", "start", "starting")
_FLOW_BODY_FIELDS = ("actions",)

# Discovers `secrets.NAME` / `event.secrets.NAME` references in action code.
_SECRET_REF_RE = re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)")


def _tokens(s: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", s.lower()) if t}


def _reference_expr(tenant: Tenant, action_key: str, name: str) -> str | None:
    """If an action-secret value is really a managed-resource id generated in the
    target tenant, return the Terraform expression to reference it (so it is not
    hardcoded). Currently handles `*_FORM_ID` -> auth0_form.<best-match>.id.
    The form is chosen by token overlap with the action key + secret name; a
    single form is used directly. Returns None when nothing matches."""
    if name.upper().endswith("_FORM_ID"):
        forms = tenant.of_type("auth0_form")
        if not forms:
            return None
        if len(forms) == 1:
            return f"auth0_form.{forms[0].key}.id"
        want = _tokens(action_key) | _tokens(name)
        best = max(forms, key=lambda f: len(_tokens(f.key) & want))
        return f"auth0_form.{best.key}.id"
    return None


def scaffold_action_secrets(tenant: Tenant) -> None:
    """Record, per auth0_action, the NAMES of the secrets its code reads.

    The Auth0 API never returns secret VALUES, so the CLI emits no secrets block.
    For each discovered `secrets.<NAME>`:
      - it resolves to a managed resource id -> `ref_secrets` (name -> Terraform
        expression, emitted module-side as a reference; not a customer secret)
      - everything else                      -> `secret_names` (list). Only the
        names go to tfvars; the values come from `var.secrets` (see secret_binding).

    Auth0 stores action configuration (ids, URLs, flags) as secrets too, so no
    attempt is made to guess which names are "really" sensitive: every name is
    listed and the customer decides how to store each one.
    Note: secrets accessed via destructuring (e.g. `const {x} = event.secrets`)
    are not auto-discovered — add those names manually.
    """
    for a in tenant.of_type("auth0_action"):
        code = a.attrs.get("code")
        if not isinstance(code, str):
            continue
        names = sorted(set(_SECRET_REF_RE.findall(code)))
        if not names:
            continue
        refs: dict[str, str] = {}
        plain: list[str] = []
        for n in names:
            expr = _reference_expr(tenant, a.key, n)
            if expr:
                refs[n] = expr
            else:
                plain.append(n)
        a.attrs["secret_names"] = plain
        if refs:
            a.attrs["ref_secrets"] = refs


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _ref(rel: str) -> dict:
    return {"__ref__": f'file("${{path.module}}/{rel}")'}


def extract_code(tenant: Tenant, modules_dir: Path) -> None:
    modules_dir = Path(modules_dir)

    for action in tenant.of_type("auth0_action"):
        code = action.attrs.get("code")
        if isinstance(code, str):
            name = action.attrs.get("name", action.key)
            # python-hcl2 leaves the source string escaped (literal \n, \", \uXXXX);
            # unescape so the written .js is real, readable source — not one line.
            _write(modules_dir / f"code/actions_code/{name}.js", _hcl_unescape(code))
            # Store a for_each-compatible ref — same expression for every instance
            # so emit_modules can hard-code it once rather than drive it via tfvars.
            action.attrs["code"] = _ref("code/actions_code/${each.value.name}.js")

    for conn in tenant.of_type("auth0_connection"):
        options = conn.attrs.get("options")
        # `options` is an HCL block, so hcl2 parses it as a single-item list of
        # dicts (with an __is_block__ marker), not a plain dict.
        if isinstance(options, list) and options and isinstance(options[0], dict):
            options = options[0]
        if not isinstance(options, dict):
            continue
        # Real provider/HCL attribute is snake_case `custom_scripts`, not
        # `customScripts` — the per-instance script-name keys vary across
        # connections, so (unlike actions/email templates) these are unescaped
        # in place rather than extracted to files (see module docstring).
        scripts = options.get("custom_scripts")
        if not isinstance(scripts, dict):
            continue
        for script_name, body in list(scripts.items()):
            if isinstance(body, str):
                scripts[script_name] = _hcl_unescape(body)


# Types whose source-tenant ids may appear *inside* form/flow JSON bodies and
# must be swapped for live resource references on apply. Restricted to opaque ids
# (safe to string-replace) — excludes stable-name types like prompt_custom_text.
_CROSS_REF_TYPES = {
    "auth0_flow", "auth0_form", "auth0_flow_vault_connection", "auth0_action",
    "auth0_connection", "auth0_client", "auth0_resource_server", "auth0_role",
    "auth0_organization",
}
# Emitted as literal blocks (auth0_x.<key>.id); all others are for_each modules
# (auth0_x.this["<key>"].id).
_LITERAL_REF_TYPES = {"auth0_form", "auth0_flow"}


def _cross_ref_index(tenant: Tenant) -> dict[str, str]:
    """source_id -> Terraform reference expression, for resources that may be
    referenced by id inside a form/flow body."""
    idx: dict[str, str] = {}
    for r in tenant.resources:
        if r.tf_type not in _CROSS_REF_TYPES or not r.source_id:
            continue
        if r.tf_type in _LITERAL_REF_TYPES:
            idx[r.source_id] = f"{r.tf_type}.{r.key}.id"
        else:
            idx[r.source_id] = f'{r.tf_type}.this["{r.key}"].id'
    return idx


def extract_form_bodies(tenant: Tenant, modules_dir: Path) -> None:
    """Extract auth0_form and auth0_flow JSON body fields to files.

    After _eval_jsonencode processes jsonencode() expressions, body fields like
    `nodes` and `actions` are JSON strings. We write each to its own file and
    replace the field value with a file() reference so the module can reference
    them without storing multi-KB JSON inline.

    auth0_form / auth0_flow are emitted as LITERAL resource blocks (one block per
    resource, keyed by resource.key — not a for_each module), so the reference
    uses the concrete, filesystem-safe key rather than `${each.value.name}`.
    """
    modules_dir = Path(modules_dir)
    idx = _cross_ref_index(tenant)
    for res_type, fields, subdir in (
        ("auth0_form", _FORM_BODY_FIELDS, "forms"),
        ("auth0_flow", _FLOW_BODY_FIELDS, "flows"),
    ):
        for resource in tenant.of_type(res_type):
            stem = resource.key
            for field in fields:
                val = resource.attrs.get(field)
                if not isinstance(val, str):
                    continue
                # Unwrap HCL escaping, then pretty-print the JSON body. Fall back
                # to the (unescaped) raw value if it does not parse as JSON.
                val = _hcl_unescape(val)
                try:
                    val = _json.dumps(_json.loads(val), indent=2, ensure_ascii=False)
                except (ValueError, TypeError):
                    pass  # keep as-is if not valid JSON
                rel = f"{subdir}/{stem}_{field}.json"
                _write(modules_dir / rel, val)
                # Source-tenant ids that other resources own can appear INSIDE the
                # body (e.g. a form node's flow_id). Swap each for the live resource
                # reference at apply time via replace(), so the body is tenant-agnostic.
                expr = f'file("${{path.module}}/{rel}")'
                for sid, ref in idx.items():
                    if sid != resource.source_id and sid in val:
                        expr = f'replace({expr}, "{sid}", {ref})'
                resource.attrs[field] = {"__ref__": expr}


def extract_email_bodies(tenant: Tenant, modules_dir: Path) -> None:
    """Extract auth0_email_template `body` content to shared files.

    Email template bodies are large liquid/HTML documents that are identical
    across environments, so keeping them in per-env terraform.tfvars is wasteful
    and duplicative. Each body is written to code/email_templates/<template>.liquid
    and the attribute is replaced with a for_each-compatible file() reference.
    Because every instance gets the SAME expression (keyed on each.value.template),
    emit_modules emits it once and drops `body` from the variable schema and tfvars.
    """
    modules_dir = Path(modules_dir)
    subdir = "code/email_templates"
    for tmpl in tenant.of_type("auth0_email_template"):
        body = tmpl.attrs.get("body")
        if not isinstance(body, str):
            continue
        name = tmpl.attrs.get("template", tmpl.key)
        _write(modules_dir / f"{subdir}/{name}.liquid", _hcl_unescape(body))
        # for_each-compatible ref — same expression for every template instance
        tmpl.attrs["body"] = _ref(f"{subdir}/${{each.value.template}}.liquid")


def extract_branding_templates(tenant: Tenant, modules_dir: Path) -> None:
    """Extract the auth0_branding Universal Login page template to a file.

    `auth0_branding.universal_login[].body` is a large HTML/liquid document that
    is the same across environments. It is written to
    branding/<key>_universal_login.html (HCL-unescaped) and replaced with a
    for_each-compatible file() reference keyed on the outer resource's each.key,
    so it leaves terraform.tfvars and renders correctly (real newlines/quotes).
    """
    modules_dir = Path(modules_dir)
    for b in tenant.of_type("auth0_branding"):
        ul = b.attrs.get("universal_login")
        if not isinstance(ul, list):
            continue
        for block in ul:
            if isinstance(block, dict) and isinstance(block.get("body"), str):
                _write(modules_dir / f"branding/{b.key}_universal_login.html",
                       _hcl_unescape(block["body"]))
                block["body"] = _ref("branding/${each.key}_universal_login.html")


def unescape_prompt_custom_text(tenant: Tenant) -> None:
    """Decode the `body` of every auth0_prompt_custom_text into readable JSON.

    The Auth0 CLI writes `body` as an escaped one-line string
    (`"{\\n    \\"login\\": ..."`). python-hcl2 strips the outer quotes but leaves the
    escapes, and tfvars heredocs do not process escapes, so Terraform would receive
    literal backslash-n / backslash-quote and `jsondecode` would reject it.

    The body is unescaped and pretty-printed (stable, readable diffs for resync).
    A body that is not valid JSON is kept as the unescaped text.

    `$${name}` sequences are left alone on purpose: Auth0 uses `$$` to escape a
    literal `${`, and a Terraform heredoc turns `$${` back into `${`.
    """
    for r in tenant.of_type("auth0_prompt_custom_text"):
        body = r.attrs.get("body")
        if not isinstance(body, str):
            continue
        body = _hcl_unescape(body)
        try:
            body = _json.dumps(_json.loads(body), indent=2, ensure_ascii=False)
        except (ValueError, TypeError):
            pass  # not JSON: keep the unescaped text
        r.attrs["body"] = body
