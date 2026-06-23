from pathlib import Path

from auth0tf.emit_pipeline import emit_azure_pipeline


def test_pipeline_has_validate_and_per_env_stages(tmp_path):
    emit_azure_pipeline(tmp_path, envs=["dev", "staging", "prod"])
    txt = (tmp_path / "azure-pipelines.yml").read_text()
    assert "stage: validate" in txt
    for env in ["dev", "staging", "prod"]:
        assert f"plan_{env}" in txt
        assert f"apply_{env}" in txt


def test_apply_dev_has_no_gate_but_staging_prod_use_environment(tmp_path):
    emit_azure_pipeline(tmp_path, envs=["dev", "staging", "prod"])
    txt = (tmp_path / "azure-pipelines.yml").read_text()
    # staging/prod approvals come from Azure DevOps Environments
    assert "environment: 'auth0-staging'" in txt
    assert "environment: 'auth0-prod'" in txt
    # no secrets inline
    assert "client_secret" not in txt.lower()
