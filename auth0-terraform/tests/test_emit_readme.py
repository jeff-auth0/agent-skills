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


def _template(txt):
    import json
    import re
    return json.loads(re.search(r"### Template.*?```json\n(.*?)\n```", txt, re.S).group(1))


def test_readme_template_lists_every_key_and_is_valid_json(tmp_path):
    secrets = [SecretSpec(f"actions.a.K{i}", "auth0_action", "a", "x") for i in range(5)]
    secrets.append(SecretSpec("flow_vault_connections.v.setup", "auth0_flow_vault_connection",
                              "v", "x", hint='{"<field>": "<value>"}'))
    txt = _readme(tmp_path, secrets=secrets)
    tpl = _template(txt)["secrets"]
    assert list(tpl) == [s.key for s in secrets]          # all keys, same order as the table
    assert tpl["actions.a.K0"] == "<value>"
    assert tpl["flow_vault_connections.v.setup"] == '{"<field>": "<value>"}'
    assert "all 6 keys" in txt
    assert "do not delete any line" in txt
    assert "stored as a string" in txt                     # explains the JSON-valued key


def test_readme_template_note_only_appears_when_a_key_needs_it(tmp_path):
    txt = _readme(tmp_path, secrets=[SecretSpec("a.b.C", "auth0_action", "b", "x")])
    assert "stored as a string" not in txt


def test_readme_no_longer_uses_the_ambiguous_sentence(tmp_path):
    txt = _readme(tmp_path, secrets=[SecretSpec("a.b.C", "auth0_action", "b", "x")])
    assert "Add one entry per row" not in txt


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
