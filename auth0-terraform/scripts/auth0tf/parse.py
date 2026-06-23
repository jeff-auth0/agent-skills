"""Parse `auth0 tf generate` HCL output into the IR.

Accepts either a single .tf file or a directory of .tf files. Uses python-hcl2.
`import` blocks are ignored (replicate model — we create resources fresh).
The Terraform resource label becomes the logical key (auth0 tf generate already
emits readable, unique labels). The source ID is taken from any matching import
block when present, else from the type's own-id attribute, else "".

NOTE: python-hcl2 8.x emits quoted identifier keys (e.g. '"auth0_client"') and
quoted string values (e.g. '"My App"'). This module normalises both so callers
always see plain Python strings.  It also strips ${...} interpolation wrappers
that 8.x emits for bare identifier references (e.g. the `to` field of an import
block) and excludes the internal '__is_block__' metadata key from attrs.
"""
from __future__ import annotations

import json as _json
import re
from pathlib import Path

import hcl2

from .model import Resource, Tenant

# The attribute that holds a resource's OWN source-tenant id, per type.
# Only types that can be referenced by other resources need an entry. This keeps
# non-target types (e.g. auth0_client_grant, whose `client_id` is a *reference*,
# not its own identity) out of the reference index.
OWN_ID_ATTR: dict[str, str] = {
    "auth0_client": "client_id",
    "auth0_resource_server": "identifier",
}

_INTERP_RE = re.compile(r"^\$\{(.+)\}$")
_JSONENCODE_RE = re.compile(r"^jsonencode\((.+)\)$")

# Map of simple jsonencode(literal) expressions to their evaluated string values.
# python-hcl2 returns these as interpolation expressions; we evaluate them so
# the tfvars contains the actual value ("null", "true", etc.) not the function call.
_JSONENCODE_LITERALS = {"null": "null", "true": "true", "false": "false"}


def _unmangle_keys_recursive(v: object) -> object:
    """Restore _kw_if/_kw_then/_kw_else keys back to if/then/else after JSON extraction."""
    if isinstance(v, dict):
        return {_unmangle_key(k): _unmangle_keys_recursive(val) for k, val in v.items()}
    if isinstance(v, list):
        return [_unmangle_keys_recursive(x) for x in v]
    return v


def _eval_jsonencode(expr: str) -> object:
    """Evaluate a jsonencode() expression from generated HCL.

    Simple literals (null, true, false) are returned as their JSON string equivalents.
    Complex HCL arguments are re-parsed with hcl2 and JSON-encoded so the result is
    a proper JSON string (not the raw function-call text). Falls back to returning
    the original expression string if re-parsing fails.
    """
    m = _JSONENCODE_RE.match(expr)
    if not m:
        return expr
    arg = m.group(1).strip()
    if arg in _JSONENCODE_LITERALS:
        return _JSONENCODE_LITERALS[arg]
    # Complex HCL argument: re-parse with hcl2 and JSON-encode.
    # _mangle_keywords was already applied to the full source file before parsing,
    # so _kw_* keys may appear in the extracted arg; unmangle them before encoding.
    try:
        doc = hcl2.loads(f"v = {arg}\n")
        raw = doc.get("v", [None])
        if isinstance(raw, list) and raw:
            raw = raw[0]
        val = _unmangle_keys_recursive(_unquote_value(raw))
        return _json.dumps(val, ensure_ascii=False)
    except Exception:
        return expr  # fall back: keep as raw expression string


# HCL keywords that the Terraform Auth0 provider uses as attribute names inside
# jsonencode() expressions (e.g. `if = { ... }` in auth0_flow bodies).
# python-hcl2 cannot parse these, so we mangle them before loading and restore after.
_KW_MANGLE_RE = re.compile(r'\b(if|then|else)(\s*=\s*[\[{"\d])', re.MULTILINE)
_KW_UNMANGLE_RE = re.compile(r'^_kw_(if|then|else)$')


def _mangle_keywords(content: str) -> str:
    return _KW_MANGLE_RE.sub(lambda m: f"_kw_{m.group(1)}{m.group(2)}", content)


def _unmangle_key(k: str) -> str:
    m = _KW_UNMANGLE_RE.match(k)
    return m.group(1) if m else k


def _unquote_key(k: str) -> str:
    """Strip surrounding double-quotes from an identifier key if present.

    hcl2 8.x wraps resource type and label keys in double quotes,
    e.g. '"auth0_client"' instead of 'auth0_client'.
    """
    if len(k) >= 2 and k[0] == '"' and k[-1] == '"':
        return k[1:-1]
    return k


def _unquote_value(v: object) -> object:
    """Normalise a value emitted by hcl2 8.x, recursively.

    Scalars: strip surrounding `"..."` (hcl2 8.x artefact) and `${...}`
    interpolation wrappers.  Recursively normalises nested lists and dicts,
    and drops the hcl2 internal `__is_block__` key from dicts at every depth.
    """
    if v is None:
        return None
    if isinstance(v, list):
        return [_unquote_value(x) for x in v]
    if isinstance(v, dict):
        return {
            k: _unquote_value(val)
            for k, val in v.items()
            if k != "__is_block__"
        }
    if not isinstance(v, str):
        return v
    # Strip ${...} interpolation wrapper first (import `to` field and function exprs)
    m = _INTERP_RE.match(v)
    if m:
        inner = m.group(1)
        # Evaluate simple jsonencode(literal) — hcl2 can't call Terraform functions,
        # so jsonencode(null) would otherwise become the literal string "jsonencode(null)".
        if inner.startswith("jsonencode("):
            return _eval_jsonencode(inner)
        return inner
    # Strip surrounding double-quotes (plain string literals — hcl2 8.x artefact)
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _iter_files(path: Path):
    if path.is_dir():
        yield from sorted(path.glob("*.tf"))
    else:
        yield path


def _import_id_map(doc: dict) -> dict[str, str]:
    """Map 'auth0_client.my_app' -> source id, from import blocks."""
    out: dict[str, str] = {}
    for block in doc.get("import", []):
        to = block.get("to")
        sid = block.get("id")
        if to and sid:
            # Normalise both: `to` may be "${auth0_client.my_app}", `id` may be '"abc123"'
            out[str(_unquote_value(to))] = str(_unquote_value(sid))
    return out


def parse_dir(path: str | Path) -> Tenant:
    path = Path(path)
    tenant = Tenant()

    # Build a GLOBAL import ID map across all files first.
    # auth0_import.tf and auth0_generated.tf are separate files, so a per-file
    # map would miss imports when processing the generated resource blocks.
    global_id_map: dict[str, str] = {}
    parsed_docs: list[dict] = []
    for f in _iter_files(path):
        with open(f) as fh:
            content = fh.read()
        doc = hcl2.loads(_mangle_keywords(content))
        global_id_map.update(_import_id_map(doc))
        parsed_docs.append(doc)

    for doc in parsed_docs:
        id_map = global_id_map
        for block in doc.get("resource", []):
            for raw_type, bodies in block.items():
                tf_type = _unquote_key(raw_type)
                for raw_label, raw_attrs in bodies.items():
                    label = _unquote_key(raw_label)
                    # Detect block-type fields BEFORE unquoting removes __is_block__.
                    # A field is a block type when its value is a list whose items
                    # carry the __is_block__ marker that python-hcl2 inserts.
                    block_fields = {
                        _unmangle_key(k)
                        for k, v in raw_attrs.items()
                        if isinstance(v, list)
                        and any(isinstance(i, dict) and i.get("__is_block__")
                                for i in v)
                    }
                    # Normalise attribute values; skip hcl2 internal metadata key;
                    # restore any keyword attribute names mangled by _mangle_keywords
                    attrs = {
                        _unmangle_key(k): _unquote_value(v)
                        for k, v in raw_attrs.items()
                        if k not in ("__is_block__", "__comments__")
                    }
                    addr = f"{tf_type}.{label}"
                    own_attr = OWN_ID_ATTR.get(tf_type)
                    source_id = id_map.get(addr) or str(
                        (attrs.get(own_attr) if own_attr else None)
                        or attrs.get("id")
                        or ""
                    )
                    tenant.add(
                        Resource(
                            tf_type=tf_type,
                            key=label,
                            source_id=source_id,
                            attrs=dict(attrs),
                            block_fields=block_fields,
                        )
                    )
    return tenant
