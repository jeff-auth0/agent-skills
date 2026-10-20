"""The ``var.secrets`` key contract, shared by the emitters and the binder.

Every customer-supplied secret is one entry in a single ``map(string)`` variable
called ``secrets``. Keys are flat, dotted and predictable:

    <variable>.<resource key>.<attribute path>     multi-instance types
    <variable>.<attribute path>                    singleton types

    actions.easy_visit_pipeline.PATIENT_ROLE_ID
    connections.my_google.client_secret
    log_streams.sonic_splunk.splunk_token
    email_provider.api_key                         (singleton: no resource key)

``<variable>`` is the tfvars variable name for the resource type. Wrapper blocks
that carry no meaning of their own (``credentials``, ``options``, ``sink``) are
dropped from the attribute path to keep keys short.

How the values reach ``var.secrets`` (vault, CI variables, a local file ...) is the
customer's responsibility; this module only defines the names.
"""
from __future__ import annotations

# Types a tenant can only have one of. Their resource key adds nothing, so it is
# left out of the secret key (email_provider.api_key, not
# email_provider.email_provider.api_key).
SINGLETON_TYPES = frozenset({
    "auth0_email_provider",
    "auth0_phone_provider",
    "auth0_guardian",
    "auth0_attack_protection",
})

# Wrapper blocks dropped from the attribute path of a key.
_WRAPPER_BLOCKS = frozenset({"credentials", "options", "sink"})

# Placeholder replaced by the resource key inside a Terraform string template.
EACH_KEY = "${each.key}"


def _path(path: tuple[str, ...], attr: str) -> list[str]:
    return [p for p in path if p not in _WRAPPER_BLOCKS] + [attr]


def key_template(var_name: str, singleton: bool, path: tuple[str, ...], attr: str) -> str:
    """Key as a Terraform string template, valid inside a for_each resource."""
    parts = [var_name] + ([] if singleton else [EACH_KEY]) + _path(path, attr)
    return ".".join(parts)


def concrete_key(var_name: str, singleton: bool, resource_key: str,
                 path: tuple[str, ...], attr: str) -> str:
    """The literal key a customer must provide, for one specific resource."""
    parts = [var_name] + ([] if singleton else [resource_key]) + _path(path, attr)
    return ".".join(parts)


def index_expr(template: str) -> str:
    """Hard lookup: Terraform fails the plan with the key name if it is absent."""
    return f'var.secrets["{template}"]'


def listed_expr(var_name: str, name: str) -> str:
    """Hard lookup that applies only to resources which list `name` in their
    tfvars `secret_names`. Used inside blocks shared by every instance of a type
    (connection options, log stream sink), where one instance needs a secret and
    another does not. `name` is the attribute, or "configuration.X" for a custom
    database script setting. Unlisted -> null, exactly as in the export.
    """
    return (f'contains(each.value.secret_names, "{name}") '
            f'? var.secrets["{var_name}.{EACH_KEY}.{name}"] : null')
