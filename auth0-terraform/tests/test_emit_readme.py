from auth0tf.emit_readme import emit_readme
from auth0tf.model import SecretSpec


def _readme(tmp_path, **kw):
    emit_readme(tmp_path, counts={"auth0_client": 2, "auth0_role": 1},
                envs=["dev", "staging"], unresolved=[], active_env="dev", **kw)
    return (tmp_path / "README.md").read_text()


def test_readme_lists_counts_and_getting_started(tmp_path):
    emit_readme(tmp_path, counts={"auth0_client": 2, "auth0_role": 1},
                envs=["dev", "staging"], unresolved=["WEIRD_ID"], active_env="dev")
    txt = (tmp_path / "README.md").read_text()
    assert "| `auth0_client` | 2 |" in txt
    assert "terraform init" in txt and "cd envs/dev" in txt
    assert "WEIRD_ID" in txt            # flagged for manual review
    assert "Terraform 1.11" in txt      # prerequisite


def test_readme_secrets_table_lists_every_key(tmp_path):
    secrets = [
        SecretSpec("email_provider.api_key", "auth0_email_provider", "email_provider",
                   "Email provider credential"),
        SecretSpec("actions.my_action.API_KEY", "auth0_action", "my_action", "Read by action"),
    ]
    txt = _readme(tmp_path, secrets=secrets)
    assert "### Required keys (2)" in txt
    assert "| `email_provider.api_key` |" in txt
    assert "| `actions.my_action.API_KEY` |" in txt
    assert "TF_VAR_secrets" in txt
    assert "secrets.auto.tfvars.json" in txt


def test_readme_states_customer_owns_binding_and_names_no_vendor(tmp_path):
    txt = _readme(tmp_path, secrets=[])
    assert "your responsibility" in txt
    assert "needs no customer-supplied secrets" in txt
    for vendor in ("Azure", "azurerm", "Key Vault", "AWS", "GitHub Actions", "Azure DevOps"):
        assert vendor not in txt, vendor


def test_readme_lists_unbound_sensitive_settings(tmp_path):
    txt = _readme(tmp_path, secrets=[], review_notes=["`auth0_hook`: secrets"])
    assert "not handled automatically" in txt
    assert "`auth0_hook`: secrets" in txt
