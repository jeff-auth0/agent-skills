"""Intermediate representation for parsed Auth0 Terraform resources."""
from __future__ import annotations

import re
from dataclasses import dataclass, field


def slugify(name: str, seen: set[str] | None = None) -> str:
    """Convert a display name into a unique snake_case key."""
    slug = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
    if not slug:
        slug = "resource"
    if seen is None:
        return slug
    candidate = slug
    n = 2
    while candidate in seen:
        candidate = f"{slug}_{n}"
        n += 1
    seen.add(candidate)
    return candidate


@dataclass
class Resource:
    tf_type: str               # e.g. "auth0_client"
    key: str                   # logical map key, e.g. "my_app"
    source_id: str             # source-tenant ID (for reference lookup)
    attrs: dict                # attribute name -> value (may be nested)
    block_fields: set = field(default_factory=set)  # fields that use HCL block syntax


@dataclass
class Tenant:
    resources: list[Resource] = field(default_factory=list)

    def add(self, r: Resource) -> None:
        self.resources.append(r)

    def types(self) -> list[str]:
        return list(dict.fromkeys(r.tf_type for r in self.resources))

    def of_type(self, tf_type: str) -> list[Resource]:
        return [r for r in self.resources if r.tf_type == tf_type]
