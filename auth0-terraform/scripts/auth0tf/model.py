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
class SecretSpec:
    """One customer-supplied secret, as it appears in ``var.secrets``.

    The binder (secret_binding.py) creates these while rewriting resource
    attributes into ``var.secrets[...]`` lookups. The same list drives the
    required-keys check in envs/<env>/secrets.tf and the README secrets table, so
    the documentation can never drift from the generated Terraform.
    """
    key: str            # exact key the customer must provide, e.g. "email_provider.api_key"
    tf_type: str        # resource type it belongs to, e.g. "auth0_email_provider"
    resource: str       # resource key within that type
    purpose: str        # one-line human description
    hint: str = "<value>"   # placeholder shown in the README template


@dataclass
class Tenant:
    resources: list[Resource] = field(default_factory=list)

    # --- results of secret_binding.bind_secrets(); read by the emitters ---------
    # Every customer-supplied secret (drives secrets.tf checks and the README).
    secrets: list[SecretSpec] = field(default_factory=list)
    # tf_type -> {top-level attribute: Terraform expression}. The attribute is
    # emitted as `attr = <expr>` instead of reading each.value.<attr>.
    field_overrides: dict[str, dict[str, str]] = field(default_factory=dict)
    # tf_type -> {block: {sub-attribute: expression}}. Applied INSIDE the dynamic
    # block of a type with several instances (connection options, log stream sink).
    block_overrides: dict[str, dict[str, dict[str, str]]] = field(default_factory=dict)
    # tf_type -> {block: {attribute: expression}}. Replaces the block with a static
    # `block { ... }` (singleton types such as the email provider credentials).
    static_blocks: dict[str, dict[str, dict[str, str]]] = field(default_factory=dict)
    # Secrets the tool cannot bind automatically; listed in the README.
    review_notes: list[str] = field(default_factory=list)

    def add(self, r: Resource) -> None:
        self.resources.append(r)

    def types(self) -> list[str]:
        return list(dict.fromkeys(r.tf_type for r in self.resources))

    def of_type(self, tf_type: str) -> list[Resource]:
        return [r for r in self.resources if r.tf_type == tf_type]
