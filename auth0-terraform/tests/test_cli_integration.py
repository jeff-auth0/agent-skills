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
    )
    assert (out / "modules" / "applications.tf").exists()
    assert (out / "modules" / "client_grants.tf").exists()
    assert (out / "modules" / "variables.tf").exists()
    assert (out / "envs" / "dev" / "main.tf").exists()
    assert (out / "envs" / "staging" / "main.tf").exists()
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


def test_transform_subcommand_generates_project(tmp_path):
    out = tmp_path / "p"
    main(["transform", "--input", str(FIX / "simple_tenant.tf"),
          "--out", str(out), "--env", "dev"])
    assert (out / "modules").exists()
    assert (out / "envs" / "dev").exists()


def test_pipeline_subcommand_is_gone(tmp_path):
    import pytest
    with pytest.raises(SystemExit):
        main(["pipeline", "--project-dir", str(tmp_path), "--envs", "dev", "--cicd", "none"])


def test_generated_project_has_no_vendor_specific_secret_wiring(tmp_path):
    out = tmp_path / "p"
    run(input_path=str(FIX / "refs_tenant.tf"), out_dir=str(out), env="dev", other_envs=[])
    assert not (out / "azure-pipelines.yml").exists()
    for f in out.rglob("*"):
        if f.is_file():
            txt = f.read_text(errors="ignore")
            for banned in ("azurerm", "key_vault", "aws_secretsmanager", "_wo_version",
                           "kv_secrets"):
                assert banned not in txt, (str(f), banned)


def test_plain_string_prompt_body_is_valid_json_in_tfvars(tmp_path):
    # Regression: plain-string prompt bodies reached tfvars still escaped, so
    # Terraform's jsondecode rejected them at plan time.
    out = tmp_path / "p"
    run(input_path=str(FIX / "prompt_custom_text_plain_string.tf"), out_dir=str(out),
        env="dev", other_envs=[])
    tfvars = (out / "envs" / "dev" / "terraform.tfvars").read_text()
    # The body must be real multi-line JSON, not the one-line escaped form. (A
    # backslash-quote is still legitimate: it is JSON's own escape for the quote
    # inside the "quote" value, which the parse below proves is intact.)
    assert '"{\\n' not in tfvars and "\\n    \\" not in tfvars
    heredocs = re.findall(r"<<-(\w+)\n(.*?)\n\1", tfvars, re.S)
    bodies = [b for _s, b in heredocs if '"login"' in b]
    assert len(bodies) == 1
    # a heredoc turns $${ into ${, so mimic that before parsing
    parsed = json.loads(bodies[0].replace("$${", "${"))
    assert parsed["login"] == {"title": "Log in to ${companyName}",
                               "quote": 'say "hi"', "accent": "café"}


def test_output_is_deterministic_across_hash_seeds(tmp_path):
    # Resync diffs a fresh export against a stored baseline, so the same tenant must
    # always produce byte-identical files. Sets iterate in a different order for
    # every Python process unless PYTHONHASHSEED is fixed.
    import os
    import subprocess
    import sys
    root = Path(__file__).parent.parent
    outs = []
    for seed in ("1", "2", "3"):
        out = tmp_path / f"s{seed}"
        subprocess.run(
            [sys.executable, "-m", "scripts.auth0tf.cli", "transform",
             "--input", str(FIX / "refs_tenant.tf"), "--out", str(out), "--env", "dev",
             "--other-envs", "prod"],
            cwd=root, check=True, capture_output=True,
            env={**os.environ, "PYTHONHASHSEED": seed})
        outs.append(out)
    files = sorted(p.relative_to(outs[0]) for p in outs[0].rglob("*") if p.is_file())
    assert files
    for rel in files:
        first = (outs[0] / rel).read_bytes()
        for other in outs[1:]:
            assert (other / rel).read_bytes() == first, str(rel)
