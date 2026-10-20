"""Decide which values are customer-supplied secrets and bind them to ``var.secrets``.

Auth0 never returns secret values, so an export contains ``null`` (or nothing) where
a secret belongs. This module is the ONLY place that knows which attributes are
secrets. For each one it

  1. removes the placeholder from the resource, so it never reaches terraform.tfvars,
  2. records the Terraform expression the module must use instead (``tenant.*``
     override tables, read by emit_modules), and
  3. records a SecretSpec — one row per key — which feeds the required-keys check in
     modules/secrets.tf and the secrets table in README.md.

There is exactly one mechanism: a flat ``map(string)`` variable named ``secrets``
(see secret_keys.py for the key format). The tool does not know or care where the
customer keeps the values; binding them to a vault or CI system is theirs.

Detection is rule based, not name based (see secrets.py). Where the export carries
no signal for whether a secret is needed (e.g. whether a connection needs an
upstream client secret) the rule is stated next to the code.
"""
from __future__ import annotations

import re

from .emit_modules import TYPE_MAP, _derive_mapping
from .model import Resource, SecretSpec, Tenant
from .secret_keys import (
    SINGLETON_TYPES,
    concrete_key,
    index_expr,
    key_template,
    listed_expr,
)
from .secrets import INPUT_FIELDS, is_write_only

# Credential fields per auth0_email_provider `name`. The provider requires the whole
# set together, so non-sensitive members (domain, region, smtp_host ...) are bound
# the same way as the secret ones: one place for the customer to look.
EMAIL_PROVIDER_CREDENTIALS: dict[str, list[str]] = {
    "ms365":     ["ms365_client_id", "ms365_client_secret", "ms365_tenant_id"],
    "smtp":      ["smtp_host", "smtp_port", "smtp_user", "smtp_pass"],
    "mailgun":   ["api_key", "domain", "region"],
    "ses":       ["access_key_id", "secret_access_key", "region"],
    "azure_cs":  ["azure_cs_connection_string"],
    "sendgrid":  ["api_key"],
    "sparkpost": ["api_key", "region"],
    "mandrill":  ["api_key"],
}

# Connection strategies that have no upstream client secret. Every other strategy
# (google-oauth2, github, oidc, waad, ...) authenticates to an external provider
# and is treated as needing `client_secret`.
_NO_CLIENT_SECRET_STRATEGIES = frozenset(
    {"auth0", "email", "sms", "samlp", "ad", "adfs", "custom"})

# Log stream type -> the sink attribute that carries its secret.
_LOG_STREAM_SECRET = {
    "splunk":   "splunk_token",
    "datadog":  "datadog_api_key",
    "http":     "http_authorization",
    "segment":  "segment_write_key",
    "mixpanel": "mixpanel_service_account_password",
}

# `configuration.NAME` / `configuration["NAME"]` inside a custom database script.
_CONFIG_REF_RE = re.compile(
    r"""\bconfiguration\s*(?:\.\s*([A-Za-z_]\w*)|\[\s*['"]([^'"]+)['"]\s*\])""")

# Sensitive provider attributes this tool does NOT bind. They are only meaningful
# for features the exported tenant may use in ways that cannot be detected from the
# export (Auth0 returns null for them). Listed in the README so nothing is silent.
UNBOUND_SENSITIVE: dict[str, list[str]] = {
    "auth0_client": [
        "addons.* credentials (firebase, sap_api, azure_blob, azure_sb, layer, "
        "salesforce_*, wams)"],
    "auth0_connection": ["options.gateway_authentication.secret (SMS gateway)"],
    "auth0_attack_protection": [
        "captcha.<provider>.secret / api_key (only if a third-party CAPTCHA is active)"],
    "auth0_guardian": [
        "push.amazon_sns / direct_apns / direct_fcm credentials (only if push MFA uses them)"],
    "auth0_event_stream": ["webhook_configuration.webhook_authorization.*"],
    "auth0_hook": ["secrets"],
    "auth0_action_module": ["secrets"],
    "auth0_user": ["password"],
}


# --------------------------------------------------------------------------- helpers

def _var_name(tf_type: str) -> str:
    return TYPE_MAP[tf_type][1] if tf_type in TYPE_MAP else _derive_mapping(tf_type)[1]


def _first_block(r: Resource, name: str) -> dict | None:
    """First item of a block attribute (hcl2 parses blocks as lists of dicts)."""
    v = r.attrs.get(name)
    if isinstance(v, list) and v and isinstance(v[0], dict):
        return v[0]
    return None


def _strip_write_only(value):
    """Recursively drop `*_wo` / `*_wo_version` keys (see secrets.is_write_only)."""
    if isinstance(value, dict):
        return {k: _strip_write_only(v) for k, v in value.items() if not is_write_only(k)}
    if isinstance(value, list):
        return [_strip_write_only(v) for v in value]
    return value


class _Binder:
    def __init__(self, tenant: Tenant):
        self.t = tenant
        self._seen: set[str] = set()

    def spec(self, tf_type: str, resource: Resource, path: tuple[str, ...], attr: str,
             purpose: str) -> str:
        """Register one secret; returns the Terraform key template for it."""
        var = _var_name(tf_type)
        singleton = tf_type in SINGLETON_TYPES
        key = concrete_key(var, singleton, resource.key, path, attr)
        if key not in self._seen:
            self._seen.add(key)
            self.t.secrets.append(SecretSpec(key, tf_type, resource.key, purpose))
        return key_template(var, singleton, path, attr)


# --------------------------------------------------------------------------- binders

def _bind_actions(b: _Binder) -> None:
    """Actions: one secret per name the action code reads (event.secrets.NAME).

    Auth0 stores action configuration (ids, URLs, flags) as secrets too, so every
    discovered name is listed — whether it is truly sensitive is the customer's call.
    The names live in tfvars (`secret_names`); the values come from var.secrets.
    """
    for r in b.t.of_type("auth0_action"):
        label = r.attrs.get("name", r.key)
        for n in r.attrs.get("secret_names", []):
            b.spec("auth0_action", r, (), n, f'Secret `{n}` read by action "{label}"')


def _bind_input_fields(b: _Binder) -> None:
    """Top-level sensitive attributes listed in secrets.INPUT_FIELDS."""
    for (tf_type, attr), kind in INPUT_FIELDS.items():
        rs = [r for r in b.t.of_type(tf_type) if attr in r.attrs]
        if not rs:
            continue
        for r in rs:
            r.attrs.pop(attr)
            template = b.spec(tf_type, r, (), attr,
                              f"`{attr}` of {tf_type} `{r.key}`" +
                              (" (a JSON object, passed to the provider as a map)"
                               if kind == "json" else ""))
        expr = index_expr(template)
        if kind == "json":
            expr = f"jsondecode({expr})"
        b.t.field_overrides.setdefault(tf_type, {})[attr] = expr


def _bind_email_provider(b: _Binder) -> None:
    """Email provider credentials become a static `credentials` block."""
    for r in b.t.of_type("auth0_email_provider"):
        name = r.attrs.get("name")
        fields = EMAIL_PROVIDER_CREDENTIALS.get(name)
        if not fields:
            b.t.review_notes.append(
                f"`auth0_email_provider` uses provider `{name}`, which this tool has no "
                "credential map for. Add its `credentials` block by hand.")
            continue
        block: dict[str, str] = {}
        for f in fields:
            template = b.spec("auth0_email_provider", r, ("credentials",), f,
                              f"Email provider ({name}) credential `{f}`")
            expr = index_expr(template)
            block[f] = f"tonumber({expr})" if f.endswith("_port") else expr
        r.attrs.pop("credentials", None)
        r.block_fields.discard("credentials")
        b.t.static_blocks.setdefault("auth0_email_provider", {})["credentials"] = block


def _bind_connections(b: _Binder) -> None:
    """Connection `options`: client_secret, twilio_token and custom-DB configuration.

    `options` is one dynamic block shared by every connection, so each connection
    lists the secrets it needs in tfvars `secret_names`; the block binds only those
    (see secret_keys.listed_expr). Entries are attribute names, or
    "configuration.<NAME>" for a setting a custom database script reads.
    """
    conns = b.t.of_type("auth0_connection")
    if not conns:
        return
    for r in conns:
        opts = _first_block(r, "options")
        strategy = r.attrs.get("strategy")
        label = f'connection "{r.attrs.get("name", r.key)}"'
        names: list[str] = []

        if opts is not None:
            # Custom database scripts read `configuration.NAME`. Auth0 never returns
            # the values, so the names are recovered from the script source.
            conf: set[str] = set()
            scripts = opts.get("custom_scripts")
            if isinstance(scripts, dict):
                for body in scripts.values():
                    if isinstance(body, str):
                        for m in _CONFIG_REF_RE.finditer(body):
                            conf.add(m.group(1) or m.group(2))
            for n in sorted(conf):
                names.append(f"configuration.{n}")
                b.spec("auth0_connection", r, ("options", "configuration"), n,
                       f"Custom database script setting `{n}` of {label}")
            if strategy not in _NO_CLIENT_SECRET_STRATEGIES:
                names.append("client_secret")
                b.spec("auth0_connection", r, ("options",), "client_secret",
                       f"Client secret for the upstream `{strategy}` identity provider of {label}")
            if strategy == "sms":
                names.append("twilio_token")
                b.spec("auth0_connection", r, ("options",), "twilio_token",
                       f"Twilio auth token of {label}")
            for f in ("configuration", "client_secret", "twilio_token"):
                opts.pop(f, None)
        r.attrs["secret_names"] = names     # dense: present (maybe empty) on every connection

    b.t.block_overrides.setdefault("auth0_connection", {})["options"] = {
        "client_secret": listed_expr("connections", "client_secret"),
        "twilio_token": listed_expr("connections", "twilio_token"),
        # null (not {}) when a connection has no configuration, matching the export.
        "configuration": (
            'length([for n in each.value.secret_names : n if startswith(n, "configuration.")]) > 0 '
            '? { for n in each.value.secret_names : trimprefix(n, "configuration.") '
            '=> var.secrets["connections.${each.key}.${n}"] if startswith(n, "configuration.") } '
            ': null'),
    }


def _bind_log_streams(b: _Binder) -> None:
    """Log stream sink secret, chosen by the stream's `type`. Bound via secret_names
    like connections, because the `sink` block is shared by every stream."""
    streams = b.t.of_type("auth0_log_stream")
    if not streams:
        return
    for r in streams:
        sink = _first_block(r, "sink")
        names: list[str] = []
        if sink is not None:
            for attr in _LOG_STREAM_SECRET.values():
                sink.pop(attr, None)
            attr = _LOG_STREAM_SECRET.get(r.attrs.get("type"))
            if attr:
                names.append(attr)
                b.spec("auth0_log_stream", r, ("sink",), attr,
                       f'`{attr}` for the {r.attrs.get("type")} log stream "{r.attrs.get("name", r.key)}"')
        r.attrs["secret_names"] = names
    b.t.block_overrides.setdefault("auth0_log_stream", {})["sink"] = {
        attr: listed_expr("log_streams", attr) for attr in sorted(_LOG_STREAM_SECRET.values())
    }


def _bind_phone_provider(b: _Binder) -> None:
    """Only the Twilio provider takes an auth token; `custom` delegates to an action."""
    for r in b.t.of_type("auth0_phone_provider"):
        if r.attrs.get("name") != "twilio":
            continue
        template = b.spec("auth0_phone_provider", r, ("credentials",), "auth_token",
                          "Twilio auth token for the phone provider")
        r.attrs.pop("credentials", None)
        r.block_fields.discard("credentials")
        b.t.static_blocks.setdefault("auth0_phone_provider", {})["credentials"] = {
            "auth_token": index_expr(template)}


def _bind_guardian(b: _Binder) -> None:
    """Duo MFA, only when enabled in the exported tenant."""
    for r in b.t.of_type("auth0_guardian"):
        duo = _first_block(r, "duo")
        if not duo or duo.get("enabled") is not True:
            continue
        block = {"enabled": "true"}
        for f in ("hostname", "integration_key", "secret_key"):
            block[f] = index_expr(b.spec("auth0_guardian", r, ("duo",), f,
                                         f"Duo MFA setting `{f}`"))
        r.attrs.pop("duo", None)
        r.block_fields.discard("duo")
        b.t.static_blocks.setdefault("auth0_guardian", {})["duo"] = block


def _collect_unbound(b: _Binder) -> None:
    """Record sensitive attributes that exist in the tenant's resource types but are
    not bound, so the README can tell the customer about them."""
    for tf_type in b.t.types():
        for path in UNBOUND_SENSITIVE.get(tf_type, []):
            b.t.review_notes.append(f"`{tf_type}`: {path}")


# --------------------------------------------------------------------------- entry

def bind_secrets(tenant: Tenant) -> None:
    """Rewrite secret placeholders into ``var.secrets`` bindings. Run before emit."""
    for r in tenant.resources:
        r.attrs = _strip_write_only(r.attrs)
    b = _Binder(tenant)
    _bind_actions(b)
    _bind_input_fields(b)
    _bind_email_provider(b)
    _bind_connections(b)
    _bind_log_streams(b)
    _bind_phone_provider(b)
    _bind_guardian(b)
    _collect_unbound(b)
    tenant.secrets.sort(key=lambda s: s.key)
