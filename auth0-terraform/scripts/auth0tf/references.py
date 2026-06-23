"""Rewire inter-resource ID references from source-tenant literals into
per-instance Terraform lookups valid in a freshly created target tenant.

Strategy (matches the spec): the source-tenant literal id is dropped from the
resource's attrs and replaced with a synthetic `<field>_key` attr holding the
LOGICAL KEY of the target resource (a plain string). That key lives in
terraform.tfvars; the module then emits the actual reference as
`<field> = <target_type>.this[each.value.<field>_key].<target_attr>`.

This keeps tfvars static (no expressions) and is correct for many instances —
each grant looks up its own target by key.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .model import Tenant


@dataclass(frozen=True)
class Ref:
    """Describes a cross-resource reference that must be rewired to a Terraform
    expression so it is valid in a freshly created target tenant.

    target_type / target_attr : the resource and attribute to reference, e.g.
        auth0_client / client_id  ->  auth0_client.this["<key>"].client_id
    kind:
        "scalar" : `field` holds a single source id string.
        "list"   : `field` holds a list of source id strings.
        "nested" : `field` is a block-list; each block carries an `inner` id field.
    inner    : for kind="nested", the id field name inside each block.
    match_by : how to locate the target resource for a literal value —
        "source_id" (default) matches the target's source-tenant id, or the name
        of a target attribute (e.g. "identifier") to match the literal against.
    """
    target_type: str
    target_attr: str
    kind: str = "scalar"
    inner: str | None = None
    match_by: str = "source_id"


# (resource_type, field) -> Ref. Each entry's `field` is rewired from a hardcoded
# source-tenant id (or list / nested id) into a per-instance Terraform lookup.
REFERENCE_FIELDS: dict[tuple[str, str], Ref] = {
    # auth0_client_grant.client_id is emitted as a literal block (see
    # emit_literal_resources); the rest are for_each modules (emit_modules).
    ("auth0_client_grant", "client_id"): Ref("auth0_client", "client_id"),
    ("auth0_client_credentials", "client_id"): Ref("auth0_client", "client_id"),
    ("auth0_connection_clients", "connection_id"): Ref("auth0_connection", "id"),
    ("auth0_connection_clients", "enabled_clients"):
        Ref("auth0_client", "client_id", kind="list"),
    ("auth0_trigger_actions", "actions"):
        Ref("auth0_action", "id", kind="nested", inner="id"),
    ("auth0_resource_server_scopes", "resource_server_identifier"):
        Ref("auth0_resource_server", "identifier", match_by="identifier"),
}


def key_field(field: str) -> str:
    """Name of the synthetic single-key lookup attr for a scalar reference."""
    return f"{field}_key"


def keys_field(field: str) -> str:
    """Name of the synthetic list-of-keys lookup attr for a list reference."""
    return f"{field}_keys"


def build_id_index(tenant: Tenant) -> dict[str, tuple[str, str]]:
    """source_id -> (tf_type, key).

    Only indexes types that are valid source-id reference TARGETS. This prevents
    resources that share the same source ID (e.g. auth0_client_credentials uses
    the same ID as auth0_client) from overwriting the correct target entry.
    """
    target_types = {ref.target_type for (_, _), ref in REFERENCE_FIELDS.items()
                    if ref.match_by == "source_id"}
    idx: dict[str, tuple[str, str]] = {}
    for r in tenant.resources:
        if r.source_id and r.tf_type in target_types:
            idx[r.source_id] = (r.tf_type, r.key)
    return idx


def _attr_index(tenant: Tenant, target_type: str, attr: str) -> dict[str, str]:
    """value-of-`attr` -> resource key, for resources of `target_type`.

    Used for references matched by a target attribute (e.g. a resource server's
    `identifier`) rather than by opaque source id.
    """
    return {r.attrs[attr]: r.key for r in tenant.of_type(target_type)
            if r.attrs.get(attr)}


MGMT_API_AUDIENCE_SENTINEL = "__mgmt_api__"
AUTH0_DOMAIN_LOGOUT_SENTINEL = "__AUTH0_DOMAIN_LOGOUT__"


def rewire_domain_audiences(tenant: Tenant) -> None:
    """Replace tenant-specific Management API audience URLs with a sentinel.

    auth0_client_grant resources that target `https://<domain>/api/v2/` have a
    hardcoded domain in their audience. We replace it with a sentinel so the
    module can reconstruct the correct URL from var.auth0_domain at apply time.
    """
    for r in tenant.of_type("auth0_client_grant"):
        audience = r.attrs.get("audience")
        if isinstance(audience, str) and audience.endswith("/api/v2/"):
            r.attrs["audience"] = MGMT_API_AUDIENCE_SENTINEL


# Built-in Auth0 resource servers that every tenant auto-provisions, keyed by the
# identifier suffix that distinguishes them. These are created automatically in a
# fresh tenant (with their default scope catalogues), so replicating them is
# redundant and conflicts with the tenant's built-ins.
_BUILTIN_API_SUFFIXES: dict[str, str] = {
    "/api/v2/": "Management API",
    "/me/": "My Account API",
}


def _builtin_api_label(identifier: str) -> str | None:
    """Return the built-in API label for an identifier, or None if it is custom."""
    for suffix, label in _BUILTIN_API_SUFFIXES.items():
        if identifier.endswith(suffix):
            return label
    return None


def exclude_builtin_apis(tenant: Tenant) -> list[str]:
    """Drop built-in Auth0 resource servers and their default scopes.

    Auth0 auto-provisions the Management API (`https://<domain>/api/v2/`) and the
    My Account API (`https://<domain>/me/`), each with its full default scope
    catalogue, in every tenant. Replicating them into a fresh tenant is redundant,
    conflicts with the auto-provisioned resources, and would otherwise leave a
    hardcoded tenant domain in their identifiers. Custom resource servers and
    custom scope sets (whose identifier matches no built-in suffix) are untouched.

    auth0_client_grant audiences that target the Management API already use the
    MGMT_API_AUDIENCE_SENTINEL (see rewire_domain_audiences) — a plain string, not
    a resource reference — so they are unaffected by this removal.

    Must run BEFORE rewire(): once a built-in resource server is gone, any
    auth0_resource_server_scopes that matched it by identifier is also gone, so
    rewire() never sees a dangling reference to resolve.

    Returns human-readable descriptions of what was removed (for the CLI/README
    report).
    """
    removed: list[str] = []
    keep: list[Resource] = []
    for r in tenant.resources:
        if r.tf_type == "auth0_resource_server":
            label = _builtin_api_label(str(r.attrs.get("identifier", "")))
            if label:
                removed.append(
                    f'auth0_resource_server "{r.key}" (built-in {label})')
                continue
        if r.tf_type == "auth0_resource_server_scopes":
            label = _builtin_api_label(
                str(r.attrs.get("resource_server_identifier", "")))
            if label:
                n = len(r.attrs.get("scopes", []) or [])
                removed.append(
                    f'auth0_resource_server_scopes "{r.key}" '
                    f"({n} default {label} scopes)")
                continue
        keep.append(r)
    tenant.resources = keep
    return removed


def rewire_domain_logout_urls(tenant: Tenant) -> None:
    """Replace tenant-specific Auth0 logout URLs with a sentinel.

    auth0_client.allowed_logout_urls entries ending in /v2/logout point at the
    tenant-local Auth0 logout endpoint. Replaced with AUTH0_DOMAIN_LOGOUT_SENTINEL
    so the module computes "https://${var.auth0_domain}/v2/logout" at apply time.
    """
    for r in tenant.of_type("auth0_client"):
        urls = r.attrs.get("allowed_logout_urls")
        if isinstance(urls, list):
            r.attrs["allowed_logout_urls"] = [
                AUTH0_DOMAIN_LOGOUT_SENTINEL
                if isinstance(u, str) and u.endswith("/v2/logout")
                else u
                for u in urls
            ]


def _audience_slug(audience: str) -> str:
    """Stable short identifier for an audience value."""
    if audience == MGMT_API_AUDIENCE_SENTINEL:
        return "mgmt_api"
    slug = re.sub(r"^https?://", "", audience)
    slug = re.sub(r"[^a-z0-9]+", "_", slug.lower()).strip("_")
    return slug or "api"


def rekey_client_grants(tenant: Tenant) -> None:
    """Replace env-specific, source-ID-derived keys on auth0_client_grant with
    stable, human-readable keys of the form {client_id_key}__{audience_slug}.

    Must be called AFTER rewire() (so client_id_key is set) and AFTER
    rewire_domain_audiences() (so the __mgmt_api__ sentinel is in place).
    """
    seen: set[str] = set()
    for r in tenant.of_type("auth0_client_grant"):
        client_key = r.attrs.get("client_id_key", r.key)
        aud_slug = _audience_slug(r.attrs.get("audience", ""))
        base = f"{client_key}__{aud_slug}"
        candidate = base
        n = 2
        while candidate in seen:
            candidate = f"{base}_{n}"
            n += 1
        seen.add(candidate)
        r.key = candidate


def rewire(tenant: Tenant) -> set[str]:
    """Rewrite reference fields in place. Returns the set of unresolved ids.

    Handles three reference shapes (see Ref.kind):
      scalar : field literal id  -> synthetic `<field>_key` (target logical key),
               original field dropped.
      list   : field list of ids -> synthetic `<field>_keys` (list of keys),
               original field dropped (only when every element resolves).
      nested : field block-list  -> each block's `inner` id replaced in place with
               the target key; the block field is retained.

    Matching is by target source id (default) or by a target attribute value
    (Ref.match_by, e.g. a resource server's `identifier`).
    """
    idx = build_id_index(tenant)
    # Attribute indexes for non-source_id matches, built once per (type, attr).
    attr_idx: dict[tuple[str, str], dict[str, str]] = {}
    for (_, _), ref in REFERENCE_FIELDS.items():
        if ref.match_by != "source_id":
            attr_idx.setdefault(
                (ref.target_type, ref.match_by),
                _attr_index(tenant, ref.target_type, ref.match_by),
            )
    unresolved: set[str] = set()

    def resolve(value) -> str | None:
        """source id (or matched attr value) -> target logical key, or None."""
        if not isinstance(value, str):
            return None
        if ref.match_by == "source_id":
            hit = idx.get(value)
            return hit[1] if hit and hit[0] == ref.target_type else None
        return attr_idx.get((ref.target_type, ref.match_by), {}).get(value)

    for r in tenant.resources:
        for (rtype, field), ref in REFERENCE_FIELDS.items():
            if r.tf_type != rtype or field not in r.attrs:
                continue
            value = r.attrs[field]

            if ref.kind == "scalar":
                key = resolve(value)
                if key is not None:
                    r.attrs[key_field(field)] = key
                    del r.attrs[field]
                elif isinstance(value, str):
                    unresolved.add(value)

            elif ref.kind == "list":
                if not isinstance(value, list):
                    continue
                keys, ok = [], True
                for item in value:
                    k = resolve(item)
                    if k is None:
                        ok = False
                        if isinstance(item, str):
                            unresolved.add(item)
                    else:
                        keys.append(k)
                if ok:
                    r.attrs[keys_field(field)] = keys
                    del r.attrs[field]

            elif ref.kind == "nested":
                if not isinstance(value, list):
                    continue
                for block in value:
                    if not isinstance(block, dict) or ref.inner not in block:
                        continue
                    k = resolve(block[ref.inner])
                    if k is None:
                        if isinstance(block[ref.inner], str):
                            unresolved.add(block[ref.inner])
                    else:
                        block[ref.inner] = k  # replace source id with target key

    return unresolved
