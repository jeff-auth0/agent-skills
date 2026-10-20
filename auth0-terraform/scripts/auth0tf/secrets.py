"""Classify top-level resource fields as computed, input secret, or plain.

- computed: Auth0 generates the value (or it is a write-only rotation field).
            Never set it and never ask the customer for it. Generated values such
            as client_id / client_secret simply live in the Terraform state file.
- input:    a real secret the customer must supply through ``var.secrets``.
- plain:    not sensitive; goes to tfvars as a literal.
- internal: bookkeeping fields the generator itself adds (action secret names and
            references). Handled by dedicated emitter code, never passed through.

Classification is an explicit table, NOT name matching. Matching names such as
"token" or "secret" wrongly caught plain config like
``token_lifetime_for_anonymous_access_tokens`` and ``*_wo_version`` counters.
The table below was derived from the Auth0 provider schema
(``terraform providers schema -json``): only attributes the provider marks
``sensitive`` and that the customer must supply are listed.

Secrets nested inside blocks (log stream sinks, email credentials, connection
options, ...) are handled by ``bind_secrets`` — this module only covers
top-level attributes.
"""
from __future__ import annotations

# (tf_type, field) pairs that are read-only/Computed in the Auth0 provider.
# Setting any of these produces invalid config; the value sits in state instead.
COMPUTED_FIELDS: set[tuple[str, str]] = {
    ("auth0_client", "client_id"),
    ("auth0_client", "client_secret"),
    ("auth0_client", "signing_keys"),
    ("auth0_resource_server", "signing_secret"),
    # Auth0 generates/owns the client_credentials secret; it sits in state.
    ("auth0_client_credentials", "client_secret"),
}

# Top-level sensitive attributes the customer supplies via ``var.secrets``.
# value = how the string from var.secrets is converted before it reaches the
# provider: "string" (as is) or "json" (the secret value is a JSON object, e.g.
# the key/value ``setup`` map of a Flow vault connection).
INPUT_FIELDS: dict[tuple[str, str], str] = {
    ("auth0_flow_vault_connection", "setup"): "json",
    ("auth0_rule_config", "value"): "string",
    ("auth0_network_acl_key", "value"): "string",
}


# Fields the generator itself adds to a resource (not provider attributes).
#   secret_names : tfvars list naming the secrets this resource needs from
#                  var.secrets (never the values)
#   ref_secrets  : action secrets whose value is a reference to another resource
INTERNAL_FIELD_NAMES = frozenset({"secret_names", "ref_secrets"})


def is_write_only(field: str) -> bool:
    """``*_wo`` (write-only value) and ``*_wo_version`` (its rotation counter).

    Never emitted: the plain sensitive attribute they shadow is used instead, and
    emitting a ``*_wo_version`` without its ``*_wo`` pair fails provider validation.
    """
    return field.endswith("_wo") or field.endswith("_wo_version")


def classify_field(tf_type: str, field: str) -> str:
    if field in INTERNAL_FIELD_NAMES:
        return "internal"
    if (tf_type, field) in COMPUTED_FIELDS or is_write_only(field):
        return "computed"
    if (tf_type, field) in INPUT_FIELDS:
        return "input"
    return "plain"
