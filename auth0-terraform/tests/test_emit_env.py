from pathlib import Path

from auth0tf.model import Resource, Tenant
from auth0tf.emit_env import emit_env


def _tenant():
    t = Tenant()
    t.add(Resource("auth0_client", "my_app", "1", {"name": "My App", "app_type": "spa"}))
    t.add(Resource("auth0_connection", "google", "2",
                   {"name": "google", "strategy": "google-oauth2",
                    "client_secret": "SOURCE_SECRET"}))
    return t


def test_emit_populated_env_files(tmp_path):
    emit_env(_tenant(), tmp_path, env="dev", kv="azure", populated=True)
    for f in ["main.tf", "variables.tf", "terraform.tfvars",
              "providers.tf", "secrets.tf", "backend.tf"]:
        assert (tmp_path / f).exists(), f


def test_tfvars_contains_plain_values_only(tmp_path):
    emit_env(_tenant(), tmp_path, env="dev", kv="azure", populated=True)
    tfvars = (tmp_path / "terraform.tfvars").read_text()
    assert "applications = {" in tfvars
    assert '"My App"' in tfvars
    # input secret must NOT be written to tfvars
    assert "SOURCE_SECRET" not in tfvars


def test_azure_secrets_datasource(tmp_path):
    emit_env(_tenant(), tmp_path, env="dev", kv="azure", populated=True)
    secrets = (tmp_path / "secrets.tf").read_text()
    assert "azurerm_key_vault_secret" in secrets
    assert "connections_secrets" in secrets


def test_aws_secrets_datasource(tmp_path):
    emit_env(_tenant(), tmp_path, env="dev", kv="aws", populated=True)
    secrets = (tmp_path / "secrets.tf").read_text()
    assert "aws_secretsmanager_secret_version" in secrets


def test_skeleton_env_has_todo_stubs(tmp_path):
    emit_env(_tenant(), tmp_path, env="prod", kv="azure", populated=False)
    main = (tmp_path / "main.tf").read_text()
    assert "TODO" in main
    tfvars = (tmp_path / "terraform.tfvars").read_text()
    assert tfvars.strip().startswith("#")


def test_env_email_provider_credentials_kv(tmp_path):
    t = Tenant()
    t.add(Resource("auth0_email_provider", "email_provider", "",
                   {"name": "ms365", "enabled": True,
                    "credentials": [{"ms365_client_id": None}]},
                   block_fields={"credentials"}))
    emit_env(t, tmp_path, env="dev", kv="azure", populated=True)
    secrets = (tmp_path / "secrets.tf").read_text()
    assert 'data "azurerm_key_vault_secret" "email_provider_credentials"' in secrets
    main = (tmp_path / "main.tf").read_text()
    assert "email_provider_credentials = {" in main
    tfvars = (tmp_path / "terraform.tfvars").read_text()
    assert "ms365_client_id" not in tfvars  # credentials dropped from tfvars (KV)


def test_env_action_kv_secrets_datasource_and_passthrough(tmp_path):
    t = Tenant()
    t.add(Resource("auth0_action", "act_x", "1",
                   {"name": "act-x", "secrets": {"LOGO": ""},
                    "kv_secrets": ["CLIENT_SECRET"]}))
    emit_env(t, tmp_path, env="dev", kv="azure", populated=True)
    secrets = (tmp_path / "secrets.tf").read_text()
    assert 'data "azurerm_key_vault_secret" "actions_kv_secrets"' in secrets
    assert "kv_secrets" in secrets
    main = (tmp_path / "main.tf").read_text()
    assert "actions_kv_secrets = {" in main
    tfvars = (tmp_path / "terraform.tfvars").read_text()
    assert "secrets" in tfvars and "kv_secrets" in tfvars


def test_env_wires_new_and_unknown_types(tmp_path):
    # email_template (curated) and an unknown type must both be wired into the
    # env main.tf / variables.tf rather than dropped.
    t = Tenant()
    t.add(Resource("auth0_email_template", "verify_email", "",
                   {"template": "verify_email", "subject": "Verify"}))
    t.add(Resource("auth0_widget", "x", "", {"name": "Widget"}))
    emit_env(t, tmp_path, env="dev", kv="azure", populated=True)
    main = (tmp_path / "main.tf").read_text()
    variables = (tmp_path / "variables.tf").read_text()
    tfvars = (tmp_path / "terraform.tfvars").read_text()
    for var_name in ("email_templates", "widget"):
        assert f"{var_name} = var.{var_name}" in main
        assert f'variable "{var_name}"' in variables
        assert f"{var_name} = {{" in tfvars
