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
