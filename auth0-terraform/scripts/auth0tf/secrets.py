"""Classify resource fields as computed secret, input secret, or plain.

- computed: Auth0 generates the value on create; the provider marks it read-only.
            Never set it and never inject it — the value simply lives in the
            Terraform state file (e.g. client_id / client_secret). No output is
            emitted; these are not pushed to or pulled from a key vault.
- input:    a real EXTERNAL secret we must supply (e.g. a social connection's
            client_secret from the upstream IdP). Pull from KV via a data source.
- plain:    not sensitive; goes to tfvars as a literal.
"""
from __future__ import annotations

# (tf_type, field) pairs that are read-only/Computed in the Auth0 provider.
# Setting any of these produces invalid config; the value sits in state instead.
# These are NOT exposed as outputs and NOT injected from a key vault.
COMPUTED_FIELDS: set[tuple[str, str]] = {
    ("auth0_client", "client_id"),
    ("auth0_client", "client_secret"),
    ("auth0_client", "signing_keys"),
    ("auth0_resource_server", "signing_secret"),
    # Auth0 generates/owns the client_credentials secret; let it sit in state
    # rather than injecting it from a key vault.
    ("auth0_client_credentials", "client_secret"),
}

# Fields whose names match secret-like tokens but are plain config values.
# Without this list _looks_secret() would route them to KV data sources.
KNOWN_NOT_SECRETS: set[tuple[str, str]] = {
    ("auth0_client",          "is_token_endpoint_ip_header_trusted"),
    ("auth0_resource_server", "signing_alg"),
    ("auth0_resource_server", "token_lifetime"),
    ("auth0_resource_server", "token_lifetime_for_web"),
    ("auth0_resource_server", "token_dialect"),  # plain enum, not a secret
}

_SECRET_TOKENS = (
    "secret",
    "password",
    "token",
    "certificate",
    "signing",
    "private_key",
)


def _looks_secret(field: str) -> bool:
    f = field.lower()
    if f == "key":  # avoid matching every "*_key" id; only explicit secrets
        return True
    return any(tok in f for tok in _SECRET_TOKENS)


def classify_field(tf_type: str, field: str) -> str:
    if (tf_type, field) in COMPUTED_FIELDS:
        return "computed"
    if (tf_type, field) in KNOWN_NOT_SECRETS:
        return "plain"
    if _looks_secret(field):
        return "input"
    return "plain"
