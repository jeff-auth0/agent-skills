"""Shared helper for decoding HCL string-literal escape sequences left intact
by python-hcl2 (used by both parse.py and extract.py).
"""
from __future__ import annotations

import json as _json


def hcl_unescape(s: str) -> str:
    """Unwrap one level of HCL string escaping left intact by python-hcl2.

    python-hcl2 strips the surrounding quotes of an HCL string literal but leaves
    inner escapes (\\" \\n \\\\ \\uXXXX) untouched, so a value extracted from the
    generated config is still escaped. Re-wrapping in quotes and JSON-decoding
    recovers the real text. Falls back to the original string on any failure.
    """
    if "\\" not in s:
        return s
    try:
        return _json.loads(f'"{s}"')
    except (ValueError, TypeError):
        return s


def hcl_template_unescape(s: str) -> str:
    """Turn HCL's template escapes back into the literal text they stand for.

    In an HCL string, `$${` means a literal `${` and `%%{` a literal `%{` (otherwise
    Terraform would start an interpolation or directive). The Auth0 CLI therefore
    writes JavaScript like `${name}` as `$${name}` in the generated config.

    That escape is correct inside a .tf file or a tfvars heredoc, where Terraform
    resolves it. It is WRONG in a file read back with `file()`: Terraform does not
    process the file's content, so `$${name}` would reach the tenant unchanged and
    JavaScript would print a stray `$`. Call this on anything written to disk.
    """
    return s.replace("$${", "${").replace("%%{", "%{")
