"""Extract inline JS (action code, connection custom DB scripts) and form/flow
JSON bodies to files, replacing inline values with file() references.
"""
from __future__ import annotations

import json as _json
import re
from pathlib import Path

from .model import Tenant

# Body fields in auth0_form / auth0_flow that hold JSON strings after
# _eval_jsonencode processing. Extracted to files so tfvars stays lean.
_FORM_BODY_FIELDS = ("nodes", "ending", "start", "starting")
_FLOW_BODY_FIELDS = ("actions",)

# Discovers `secrets.NAME` / `event.secrets.NAME` references in action code.
_SECRET_REF_RE = re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)")


def _action_secret_is_kv(name: str) -> bool:
    """Heuristic: route obviously-sensitive secret names to Key Vault, leaving
    plain config (URLs, ids, flags) as hardcoded tfvars values."""
    u = name.upper()
    return ("SECRET" in u or "PASSWORD" in u or "PRIVATE_KEY" in u
            or "CREDENTIAL" in u or u.endswith("_KEY") or u.endswith("_TOKEN"))


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
    """Scaffold auth0_action `secrets` from the names referenced in each action's
    code. The Auth0 API never returns secret VALUES, so the CLI emits no secrets
    block — values must be supplied in IaC. For each discovered `secrets.<NAME>`:
      - resolves to a managed resource id -> `ref_secrets` (name -> TF expression;
        emitted as a module-side reference, not hardcoded — see emit_modules)
      - sensitive-looking name            -> `kv_secrets` (list; from Key Vault)
      - everything else                   -> `secrets`    (name->"" map; tfvars)
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
        hard: dict[str, str] = {}
        kv: list[str] = []
        for n in names:
            expr = _reference_expr(tenant, a.key, n)
            if expr:
                refs[n] = expr
            elif _action_secret_is_kv(n):
                kv.append(n)
            else:
                hard[n] = ""
        a.attrs["secrets"] = hard
        a.attrs["kv_secrets"] = kv
        if refs:
            a.attrs["ref_secrets"] = refs


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _ref(rel: str) -> dict:
    return {"__ref__": f'file("${{path.module}}/{rel}")'}


def _hcl_unescape(s: str) -> str:
    """Unwrap one level of HCL string escaping left intact by python-hcl2.

    python-hcl2 strips the surrounding quotes of an HCL string literal but leaves
    inner escapes (\\" \\n \\\\ \\uXXXX) untouched, so a body extracted from the
    generated config is still escaped. Re-wrapping in quotes and JSON-decoding
    recovers the real text. Falls back to the original string on any failure.
    """
    if "\\" not in s:
        return s
    try:
        return _json.loads(f'"{s}"')
    except (ValueError, TypeError):
        return s


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
        if not isinstance(options, dict):
            continue
        scripts = options.get("customScripts")
        if not isinstance(scripts, dict):
            continue
        conn_name = conn.attrs.get("name", conn.key)
        for script_name, body in list(scripts.items()):
            if isinstance(body, str):
                rel = f"scripts/{conn_name}/{script_name}.js"
                _write(modules_dir / rel, _hcl_unescape(body))
                scripts[script_name] = _ref(rel)


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
