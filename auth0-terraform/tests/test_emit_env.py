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
    emit_env(_tenant(), tmp_path, env="dev", populated=True)
    for f in ["main.tf", "variables.tf", "terraform.tfvars",
              "providers.tf", "secrets.tf", "backend.tf"]:
        assert (tmp_path / f).exists(), f


def test_tfvars_contains_plain_values_only(tmp_path):
    emit_env(_tenant(), tmp_path, env="dev", populated=True)
    tfvars = (tmp_path / "terraform.tfvars").read_text()
    assert "applications = {" in tfvars
    assert '"My App"' in tfvars


def test_skeleton_env_has_todo_stubs(tmp_path):
    emit_env(_tenant(), tmp_path, env="prod", populated=False)
    main = (tmp_path / "main.tf").read_text()
    assert "TODO" in main
    tfvars = (tmp_path / "terraform.tfvars").read_text()
    assert tfvars.strip().startswith("#")


def test_env_wires_new_and_unknown_types(tmp_path):
    # email_template (curated) and an unknown type must both be wired into the
    # env main.tf / variables.tf rather than dropped.
    t = Tenant()
    t.add(Resource("auth0_email_template", "verify_email", "",
                   {"template": "verify_email", "subject": "Verify"}))
    t.add(Resource("auth0_widget", "x", "", {"name": "Widget"}))
    emit_env(t, tmp_path, env="dev", populated=True)
    main = (tmp_path / "main.tf").read_text()
    variables = (tmp_path / "variables.tf").read_text()
    tfvars = (tmp_path / "terraform.tfvars").read_text()
    for var_name in ("email_templates", "widget"):
        assert f"{var_name} = var.{var_name}" in main
        assert f'variable "{var_name}"' in variables
        assert f"{var_name} = {{" in tfvars


def test_env_declares_one_secrets_variable_and_passes_it_to_the_module(tmp_path):
    emit_env(_tenant(), tmp_path, env="dev", populated=True)
    secrets = (tmp_path / "secrets.tf").read_text()
    assert 'variable "secrets"' in secrets
    assert "map(string)" in secrets and "sensitive" in secrets
    assert "your responsibility" in secrets
    main = (tmp_path / "main.tf").read_text()
    assert "secrets      = var.secrets" in main


def test_env_has_no_vendor_scaffolds_or_per_type_secret_variables(tmp_path):
    emit_env(_tenant(), tmp_path, env="dev", populated=True)
    for f in ("secrets.tf", "main.tf", "variables.tf", "backend.tf"):
        txt = (tmp_path / f).read_text()
        for banned in ("azurerm", "Key Vault", "aws_secretsmanager", "GitHub Actions",
                       "connections_secrets", "actions_secrets", "kv_secrets", "Option A"):
            assert banned not in txt, (f, banned)


def test_action_secret_names_are_in_tfvars_but_values_never(tmp_path):
    t = Tenant()
    t.add(Resource("auth0_action", "act_x", "1",
                   {"name": "act-x", "secret_names": ["CLIENT_SECRET", "LOGO"]}))
    t.add(Resource("auth0_action", "act_y", "2", {"name": "act-y"}))   # no secrets
    emit_env(t, tmp_path, env="dev", populated=True)
    tfvars = (tmp_path / "terraform.tfvars").read_text()
    assert 'secret_names' in tfvars and '"CLIENT_SECRET"' in tfvars
    assert "kv_secrets" not in tfvars


def test_backend_stub_is_vendor_neutral(tmp_path):
    emit_env(_tenant(), tmp_path, env="dev", populated=True)
    backend = (tmp_path / "backend.tf").read_text()
    assert "TODO" in backend and "state" in backend
    for banned in ('backend "azurerm"', 'backend "s3"', 'backend "gcs"', "Azure", "AWS"):
        assert banned not in backend
