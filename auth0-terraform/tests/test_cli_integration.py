import json
import re
from pathlib import Path

from auth0tf.cli import main, run

FIX = Path(__file__).parent / "fixtures"


def test_end_to_end_generates_full_tree(tmp_path):
    out = tmp_path / "auth0-terraform"
    run(
        input_path=str(FIX / "refs_tenant.tf"),
        out_dir=str(out),
        env="dev",
        other_envs=["staging"],
        cicd="azure-pipelines",
    )
    assert (out / "modules" / "applications.tf").exists()
    assert (out / "modules" / "client_grants.tf").exists()
    assert (out / "modules" / "variables.tf").exists()
    assert (out / "envs" / "dev" / "main.tf").exists()
    assert (out / "envs" / "staging" / "main.tf").exists()
    assert (out / "azure-pipelines.yml").exists()
    assert (out / "README.md").exists()
    # reference rewiring happened: client_grant literal block references the
    # auth0_client resource by its state key (no hardcoded client id).
    grants = (out / "modules" / "client_grants.tf").read_text()
    assert 'auth0_client.this["my_app"].client_id' in grants
    # grants are self-contained literal blocks — no client_id_key in tfvars —
    # but the client itself is driven by tfvars.
    tfvars = (out / "envs" / "dev" / "terraform.tfvars").read_text()
    assert "my_app" in tfvars


def test_prompt_custom_text_and_custom_scripts_survive_full_pipeline(tmp_path):
    # Regression test for the double-escaped-JSON bug: prompt_custom_text
    # bodies and connection custom_scripts must reach terraform.tfvars with
    # real newlines/quotes, not literal backslash-n/backslash-quote sequences
    # that Terraform heredocs pass through verbatim (invalid JSON at plan time).
    out = tmp_path / "p"
    run(
        input_path=str(FIX / "prompt_custom_text_and_scripts_tenant.tf"),
        out_dir=str(out),
        env="dev",
        other_envs=[],
        cicd="none",
    )
    tfvars = (out / "envs" / "dev" / "terraform.tfvars").read_text()
    # A single backslash before n/" (JSON's own escaping of a real newline/quote
    # inside a string value) is correct. Two consecutive backslashes is the
    # double-escaping bug's signature — it should never appear.
    assert "\\\\" not in tfvars

    heredocs = re.findall(r"<<-(\w+)\n(.*?)\n\1", tfvars, re.S)
    bodies = [body for _sentinel, body in heredocs if "signup-id" in body]
    assert len(bodies) == 1
    parsed = json.loads(bodies[0])
    assert parsed == {
        "signup-id": {
            "description": "Sign up for an account.\nPlease continue.",
            "title": 'Create your "account"',
        }
    }
    assert "callback(null, user);" in tfvars


def test_cicd_none_skips_pipeline(tmp_path):
    out = tmp_path / "p"
    run(input_path=str(FIX / "simple_tenant.tf"), out_dir=str(out),
        env="dev", other_envs=[], cicd="none")
    assert not (out / "azure-pipelines.yml").exists()


def test_transform_subcommand_no_pipeline(tmp_path):
    out = tmp_path / "p"
    main(["transform", "--input", str(FIX / "simple_tenant.tf"),
          "--out", str(out), "--env", "dev"])
    assert not (out / "azure-pipelines.yml").exists()
    assert (out / "modules").exists()
    assert (out / "envs" / "dev").exists()


def test_pipeline_subcommand_generates_yml(tmp_path):
    main(["pipeline", "--project-dir", str(tmp_path),
          "--envs", "dev,staging", "--cicd", "azure-pipelines"])
    yml = (tmp_path / "azure-pipelines.yml")
    assert yml.exists()
    txt = yml.read_text()
    assert "stage: validate" in txt
    assert "plan_dev" in txt
    assert "plan_staging" in txt
