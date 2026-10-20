
from auth0tf.model import Resource, Tenant
from auth0tf.emit_modules import emit_literal_resources, emit_modules

TYPE_FILE = {"auth0_client": "applications.tf", "auth0_role": "roles.tf"}


def _tenant():
    t = Tenant()
    t.add(Resource("auth0_client", "my_app", "1",
                   {"name": "My App", "app_type": "spa",
                    "client_secret": "GENERATED"}))
    t.add(Resource("auth0_role", "viewer", "2", {"name": "Viewer", "description": "ro"}))
    return t


def test_emit_writes_one_file_per_present_type(tmp_path):
    emit_modules(_tenant(), tmp_path)
    assert (tmp_path / "applications.tf").exists()
    assert (tmp_path / "roles.tf").exists()
    # absent types produce no file
    assert not (tmp_path / "apis.tf").exists()


def test_emit_uses_for_each_block(tmp_path):
    emit_modules(_tenant(), tmp_path)
    txt = (tmp_path / "applications.tf").read_text()
    assert 'resource "auth0_client" "this"' in txt
    assert "for_each = local.apps_resolved" in txt
    assert "name     = each.value.name" in txt


def test_emit_variables_typed_map(tmp_path):
    emit_modules(_tenant(), tmp_path)
    txt = (tmp_path / "variables.tf").read_text()
    assert 'variable "applications"' in txt
    assert "map(object({" in txt
    assert "app_type = string" in txt
    assert "default = {}" in txt


def test_computed_secret_not_emitted_as_output(tmp_path):
    # computed Auth0-generated secrets sit in the state file: NOT set as attrs,
    # NOT exposed as outputs, NOT injected from KV.
    t = _tenant()
    emit_modules(t, tmp_path)
    outputs = (tmp_path / "outputs.tf").read_text()
    assert outputs.strip() == ""  # no computed-secret outputs
    apps = (tmp_path / "applications.tf").read_text()
    assert "client_secret" not in apps  # not set on the resource


def test_emit_reference_field_uses_literal_client_reference(tmp_path):
    # client_grants are emitted as literal blocks (LITERAL_TYPE_MAP) by
    # emit_literal_resources, with client_id resolved to a direct keyed
    # reference to the auth0_client resource (state-managed, no hardcoded id).
    t = Tenant()
    t.add(Resource("auth0_client", "my_app", "1", {"name": "My App"}))
    t.add(Resource("auth0_client_grant", "g", "",
                   {"client_id_key": "my_app", "audience": "https://api"}))
    emit_literal_resources(t, tmp_path)
    txt = (tmp_path / "client_grants.tf").read_text()
    assert 'client_id = auth0_client.this["my_app"].client_id' in txt
    # the synthetic key is consumed for the reference, not emitted as an attribute
    assert "client_id_key" not in txt


def test_email_template_emitted_with_curated_name(tmp_path):
    # auth0_email_template is in TYPE_MAP -> curated filename, NOT silently dropped,
    # and does NOT appear in the generic-types list.
    t = Tenant()
    t.add(Resource("auth0_email_template", "verify_email", "",
                   {"template": "verify_email", "subject": "Verify", "enabled": True}))
    generic = emit_modules(t, tmp_path)
    assert (tmp_path / "email_templates.tf").exists()
    txt = (tmp_path / "email_templates.tf").read_text()
    assert 'resource "auth0_email_template" "this"' in txt
    assert "for_each = var.email_templates" in txt
    # ordering caveat documented in the file header
    assert "auth0_email_provider must be configured BEFORE" in txt
    # variable schema is wired
    vars_txt = (tmp_path / "variables.tf").read_text()
    assert 'variable "email_templates"' in vars_txt
    assert "auth0_email_template" not in generic  # curated, not generic


def test_for_each_scalar_list_nested_refs_emit_lookups(tmp_path):
    # association resources emitted as for_each modules must reference targets by
    # key (no hardcoded source ids), and keep the synthetic lookup keys in the
    # variable schema (the module reads them from tfvars).
    from auth0tf.references import rewire
    t = Tenant()
    t.add(Resource("auth0_client", "app_a", "CID_A", {"name": "App A"}))
    t.add(Resource("auth0_client", "app_b", "CID_B", {"name": "App B"}))
    t.add(Resource("auth0_connection", "db", "con_1", {"name": "db"}))
    t.add(Resource("auth0_action", "act_x", "uuid_1", {"name": "x"}))
    t.add(Resource("auth0_connection_clients", "cx", "con_1",
                   {"connection_id": "con_1", "enabled_clients": ["CID_A", "CID_B"]}))
    t.add(Resource("auth0_trigger_actions", "post_login", "",
                   {"trigger": "post-login",
                    "actions": [{"display_name": "x", "id": "uuid_1"}]},
                   block_fields={"actions"}))
    rewire(t)
    emit_modules(t, tmp_path)

    cc = (tmp_path / "connection_clients.tf").read_text()
    assert "connection_id = auth0_connection.this[each.value.connection_id_key].id" in cc
    assert ("enabled_clients = [for k in each.value.enabled_clients_keys : "
            "auth0_client.this[k].client_id]") in cc
    assert "CID_A" not in cc and "con_1" not in cc  # no hardcoded source ids

    ta = (tmp_path / "trigger_actions.tf").read_text()
    assert 'dynamic "actions"' in ta
    assert "id           = auth0_action.this[actions.value.id].id" in ta
    assert "uuid_1" not in ta

    # synthetic lookup keys must be declared in the variable schema
    variables = (tmp_path / "variables.tf").read_text()
    assert "connection_id_key" in variables
    assert "enabled_clients_keys" in variables


def test_action_reference_secret_emits_locals_and_lookup(tmp_path):
    # reference-valued action secrets go into a locals block (resource refs can't
    # live in tfvars) and are merged into the secrets block via lookup per action.
    t = Tenant()
    t.add(Resource("auth0_form", "form_profile_enrollement", "", {"name": "f"}))
    t.add(Resource("auth0_action", "progressive_profiling", "1",
                   {"name": "progressive-profiling", "secret_names": [],
                    "ref_secrets": {"PROGRESSIVE_PROFILING_FORM_ID":
                                    "auth0_form.form_profile_enrollement.id"}}))
    emit_modules(t, tmp_path)
    txt = (tmp_path / "actions.tf").read_text()
    assert "locals {" in txt and "action_secret_refs = {" in txt
    assert ("PROGRESSIVE_PROFILING_FORM_ID = "
            "auth0_form.form_profile_enrollement.id") in txt
    assert "lookup(local.action_secret_refs, each.key, {})" in txt


def test_literal_form_body_ref_emits_file_expression(tmp_path):
    # extract_form_bodies replaces a form's JSON body field with a __ref__ dict;
    # emit_literal_resources must emit the raw file() expression, not an object.
    t = Tenant()
    t.add(Resource("auth0_form", "my_form", "", {
        "name": "my_form",
        "nodes": {"__ref__": 'file("${path.module}/forms/${each.value.name}_nodes.json")'},
    }))
    emit_literal_resources(t, tmp_path)
    txt = (tmp_path / "forms.tf").read_text()
    assert 'nodes = file("${path.module}/forms/${each.value.name}_nodes.json")' in txt
    # must NOT render the ref as an HCL object
    assert "__ref__" not in txt


def test_unknown_type_emitted_via_generic_fallback(tmp_path):
    # A type absent from both maps must still be emitted (never silently dropped)
    # and reported in the returned generic-types list.
    t = Tenant()
    t.add(Resource("auth0_log_stream", "splunk", "",
                   {"name": "Splunk", "type": "splunk"}))
    t.add(Resource("auth0_widget", "x", "", {"name": "Widget"}))  # truly unknown
    generic = emit_modules(t, tmp_path)
    # auth0_log_stream is curated in TYPE_MAP
    assert (tmp_path / "log_streams.tf").exists()
    assert "auth0_log_stream" not in generic
    # auth0_widget -> derived stem "widget"
    assert (tmp_path / "widget.tf").exists()
    txt = (tmp_path / "widget.tf").read_text()
    assert 'resource "auth0_widget" "this"' in txt
    assert "for_each = var.widget" in txt
    assert generic == ["auth0_widget"]


def test_action_secrets_come_from_var_secrets(tmp_path):
    t = Tenant()
    t.add(Resource("auth0_action", "act_x", "1",
                   {"name": "act-x", "runtime": "node22", "secret_names": ["A", "B"]}))
    emit_modules(t, tmp_path)
    actions = (tmp_path / "actions.tf").read_text()
    assert 'dynamic "secrets"' in actions
    assert 'var.secrets["actions.${each.key}.${n}"]' in actions
    assert "name  = secrets.key" in actions and "value = secrets.value" in actions
    assert "kv_secrets" not in actions and "secrets_wo_version" not in actions
    assert "SECRETS" in actions                 # explanatory comment
    variables = (tmp_path / "variables.tf").read_text()
    assert "secret_names" in variables and "optional(list(string), [])" in variables


def test_module_secrets_tf_declares_variable_and_required_key_check(tmp_path):
    t = Tenant()
    t.add(Resource("auth0_action", "act_x", "1",
                   {"name": "act-x", "secret_names": ["A"]}))
    emit_modules(t, tmp_path)
    txt = (tmp_path / "secrets.tf").read_text()
    assert 'variable "secrets"' in txt and "map(string)" in txt and "sensitive" in txt
    assert '"actions.${k}.${n}"' in txt
    assert "missing_secret_keys" in txt
    assert 'precondition' in txt and "Missing required secrets" in txt
    assert "nonsensitive(keys(var.secrets))" in txt


def test_email_provider_credentials_render_as_static_block(tmp_path):
    t = Tenant()
    t.add(Resource("auth0_email_provider", "email_provider", "",
                   {"name": "mailgun", "enabled": True,
                    "credentials": [{"api_key": None}]}, block_fields={"credentials"}))
    from auth0tf.secret_binding import bind_secrets
    bind_secrets(t)
    emit_modules(t, tmp_path)
    txt = (tmp_path / "email_provider.tf").read_text()
    assert "credentials {" in txt
    assert 'api_key = var.secrets["email_provider.api_key"]' in txt
    assert "each.value.credentials" not in txt
    secrets_tf = (tmp_path / "secrets.tf").read_text()
    assert '"email_provider.api_key"' in secrets_tf


def test_shared_block_secrets_are_bound_only_for_resources_that_list_them(tmp_path):
    t = Tenant()
    t.add(Resource("auth0_log_stream", "s", "1",
                   {"name": "S", "type": "splunk", "sink": [{"splunk_domain": "h"}]},
                   block_fields={"sink"}))
    from auth0tf.secret_binding import bind_secrets
    bind_secrets(t)
    emit_modules(t, tmp_path)
    txt = (tmp_path / "log_streams.tf").read_text()
    import re
    assert re.search(r'splunk_token\s+= contains\(each\.value\.secret_names, "splunk_token"\) '
                     r'\? var\.secrets\["log_streams\.\$\{each\.key\}\.splunk_token"\] : null', txt)


def test_no_write_only_or_per_type_secret_variables_are_emitted(tmp_path):
    from auth0tf.secret_binding import bind_secrets
    t = _tenant()
    t.add(Resource("auth0_action", "a", "1", {"name": "a", "secret_names": ["X"]}))
    bind_secrets(t)
    emit_modules(t, tmp_path)
    for f in tmp_path.glob("*.tf"):
        txt = f.read_text()
        for banned in ("_wo_version", "_secrets[", "kv_secrets", "email_provider_credentials"):
            assert banned not in txt, (f.name, banned)
