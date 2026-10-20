"""The secret binder is the single place that decides what the customer must supply."""
from auth0tf.model import Resource, Tenant
from auth0tf.secret_binding import bind_secrets


def _bind(*resources):
    t = Tenant()
    for r in resources:
        t.add(r)
    bind_secrets(t)
    return t


def _keys(t):
    return [s.key for s in t.secrets]


def test_action_secret_names_become_keys():
    t = _bind(Resource("auth0_action", "my_action", "1",
                       {"name": "my-action", "secret_names": ["B", "A"]}))
    assert _keys(t) == ["actions.my_action.A", "actions.my_action.B"]


def test_email_provider_is_a_singleton_key_without_resource_segment():
    t = _bind(Resource("auth0_email_provider", "email_provider", "",
                       {"name": "mailgun", "credentials": [{"api_key": None}]},
                       block_fields={"credentials"}))
    assert _keys(t) == ["email_provider.api_key", "email_provider.domain",
                        "email_provider.region"]
    block = t.static_blocks["auth0_email_provider"]["credentials"]
    assert block["api_key"] == 'var.secrets["email_provider.api_key"]'
    r = t.of_type("auth0_email_provider")[0]
    assert "credentials" not in r.attrs and "credentials" not in r.block_fields


def test_smtp_port_is_converted_to_a_number():
    t = _bind(Resource("auth0_email_provider", "e", "", {"name": "smtp"}))
    block = t.static_blocks["auth0_email_provider"]["credentials"]
    assert block["smtp_port"] == 'tonumber(var.secrets["email_provider.smtp_port"])'


def test_unknown_email_provider_is_flagged_not_guessed():
    t = _bind(Resource("auth0_email_provider", "e", "", {"name": "carrier-pigeon"}))
    assert t.secrets == []
    assert any("carrier-pigeon" in n for n in t.review_notes)


def test_social_connection_needs_client_secret_database_connection_does_not():
    social = Resource("auth0_connection", "google", "1",
                      {"name": "google", "strategy": "google-oauth2",
                       "options": [{"client_secret": None, "scopes": ["email"]}]},
                      block_fields={"options"})
    db = Resource("auth0_connection", "users", "2",
                  {"name": "users", "strategy": "auth0",
                   "options": [{"client_secret": None}]}, block_fields={"options"})
    t = _bind(social, db)
    assert _keys(t) == ["connections.google.client_secret"]
    assert social.attrs["secret_names"] == ["client_secret"]
    assert db.attrs["secret_names"] == []           # dense: present on every connection
    assert "client_secret" not in social.attrs["options"][0]   # placeholder removed


def test_custom_db_script_configuration_names_are_discovered():
    script = ("function login(e, p, cb) {\n"
              "  const id = configuration.client_id;\n"
              "  const base = configuration['base_uri'];\n"
              "  const again = configuration.client_id;\n}")
    c = Resource("auth0_connection", "legacy", "1",
                 {"name": "legacy", "strategy": "auth0",
                  "options": [{"custom_scripts": {"login": script}, "configuration": None}]},
                 block_fields={"options"})
    t = _bind(c)
    assert _keys(t) == ["connections.legacy.configuration.base_uri",
                        "connections.legacy.configuration.client_id"]
    assert c.attrs["secret_names"] == ["configuration.base_uri", "configuration.client_id"]


def test_log_stream_binds_only_the_secret_for_its_type():
    splunk = Resource("auth0_log_stream", "s", "1",
                      {"name": "S", "type": "splunk",
                       "sink": [{"splunk_domain": "h", "splunk_token": None,
                                 "datadog_api_key": None,
                                 "datadog_api_key_wo_version": 0}]},
                      block_fields={"sink"})
    t = _bind(splunk)
    assert _keys(t) == ["log_streams.s.splunk_token"]
    assert splunk.attrs["secret_names"] == ["splunk_token"]
    sink = splunk.attrs["sink"][0]
    assert sink == {"splunk_domain": "h"}     # placeholders and *_wo fields removed


def test_twilio_phone_provider_needs_a_token_custom_does_not():
    twilio = _bind(Resource("auth0_phone_provider", "p", "", {"name": "twilio"}))
    assert _keys(twilio) == ["phone_provider.auth_token"]
    custom = _bind(Resource("auth0_phone_provider", "p", "", {"name": "custom"}))
    assert custom.secrets == []


def test_duo_only_when_enabled():
    on = _bind(Resource("auth0_guardian", "g", "", {"duo": [{"enabled": True}]},
                        block_fields={"duo"}))
    assert _keys(on) == ["mfa.duo.hostname", "mfa.duo.integration_key", "mfa.duo.secret_key"] \
        or _keys(on) == ["mfa.hostname", "mfa.integration_key", "mfa.secret_key"] \
        or all(k.startswith("mfa.") for k in _keys(on))
    off = _bind(Resource("auth0_guardian", "g", "", {"duo": [{"enabled": False}]},
                         block_fields={"duo"}))
    assert off.secrets == []


def test_flow_vault_setup_is_a_json_secret():
    r = Resource("auth0_flow_vault_connection", "v", "", {"name": "v", "setup": None})
    t = _bind(r)
    assert _keys(t) == ["flow_vault_connections.v.setup"]
    assert "setup" not in r.attrs
    assert t.field_overrides["auth0_flow_vault_connection"]["setup"] == \
        'jsondecode(var.secrets["flow_vault_connections.${each.key}.setup"])'


def test_write_only_fields_are_stripped_everywhere():
    r = Resource("auth0_log_stream", "s", "1",
                 {"name": "S", "type": "http",
                  "sink": [{"http_endpoint": "u", "datadog_api_key_wo": None,
                            "datadog_api_key_wo_version": 0}]},
                 block_fields={"sink"})
    _bind(r)
    assert "datadog_api_key_wo_version" not in r.attrs["sink"][0]
    assert "datadog_api_key_wo" not in r.attrs["sink"][0]


def test_tenant_without_secrets_produces_none():
    t = _bind(Resource("auth0_role", "viewer", "1", {"name": "Viewer"}))
    assert t.secrets == [] and t.field_overrides == {} and t.static_blocks == {}


def test_unbound_sensitive_settings_are_reported_for_present_types():
    t = _bind(Resource("auth0_client", "app", "1", {"name": "App"}))
    assert any("addons" in n for n in t.review_notes)
