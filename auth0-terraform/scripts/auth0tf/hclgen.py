"""Render Python values as HCL text, and infer HCL type expressions.

A reference is a dict {"__ref__": "<expr>"} rendered unquoted.
"""
from __future__ import annotations

_SKIP_KEYS = frozenset(("__is_block__", "__comments__"))


class Optional:
    """Wraps a representative value to emit optional(type[, default]) in render_type."""
    __slots__ = ("value", "default")

    def __init__(self, value, default=None):
        self.value = value
        self.default = default


class Raw:
    """A pre-rendered HCL type expression emitted verbatim by render_type
    (e.g. Raw("map(string)")). Lets callers inject exact types that value
    inference can't produce."""
    __slots__ = ("text",)

    def __init__(self, text: str):
        self.text = text


def _is_ref(v) -> bool:
    return isinstance(v, dict) and set(v.keys()) == {"__ref__"}


def render_value(v, indent: int = 0) -> str:
    pad = "  " * indent
    if v is None:
        return "null"
    if _is_ref(v):
        return v["__ref__"]
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        # Use heredoc when the string contains newlines or embedded double-quotes,
        # since Terraform does not allow multi-line or unescaped-quote strings.
        if "\n" in v or '"' in v:
            sentinel = "EOT"
            while sentinel in v:
                sentinel += "_"
            return f"<<-{sentinel}\n{v}\n{sentinel}"
        return f'"{v}"'
    if isinstance(v, list):
        if not v:
            return "[]"
        items = ", ".join(render_value(x) for x in v)
        return f"[{items}]"
    if isinstance(v, dict):
        items = {k: val for k, val in v.items() if k not in _SKIP_KEYS}
        if not items:
            return "{}"
        width = max(len(k) for k in items)
        lines = []
        for k, val in items.items():
            rendered = render_value(val, indent + 1)
            lines.append(f"{pad}  {k.ljust(width)} = {rendered}")
        return "{\n" + "\n".join(lines) + f"\n{pad}}}"
    raise TypeError(f"cannot render {type(v)}")


def render_type(v, indent: int = 1) -> str:
    pad = "  " * indent
    if isinstance(v, Raw):
        return v.text
    if isinstance(v, Optional):
        inner = render_type(v.value, indent)
        if v.default is None:
            return f"optional({inner})"
        return f"optional({inner}, {render_value(v.default)})"
    if _is_ref(v):
        return "string"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        if not v:
            return "list(any)"
        return f"list({render_type(v[0], indent)})"
    if isinstance(v, dict):
        items = {k: val for k, val in v.items() if k not in _SKIP_KEYS}
        if not items:
            return "object({})"
        width = max(len(k) for k in items)
        lines = [f"{pad}  {k.ljust(width)} = {render_type(val, indent + 1)}"
                 for k, val in items.items()]
        return "object({\n" + "\n".join(lines) + f"\n{pad}}})"
    return "any"
