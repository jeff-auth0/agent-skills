import shutil
import subprocess
from pathlib import Path

import pytest

from auth0tf.cli import run

FIX = Path(__file__).parent / "fixtures"


@pytest.mark.skipif(shutil.which("terraform") is None,
                    reason="terraform CLI not installed")
def test_generated_env_passes_terraform_validate(tmp_path):
    out = tmp_path / "proj"
    run(input_path=str(FIX / "simple_tenant.tf"), out_dir=str(out),
        env="dev", other_envs=[])
    env_dir = out / "envs" / "dev"
    subprocess.run(["terraform", "init", "-backend=false"],
                   cwd=env_dir, check=True, capture_output=True)
    r = subprocess.run(["terraform", "validate"],
                       cwd=env_dir, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + r.stdout


@pytest.mark.skipif(shutil.which("terraform") is None,
                    reason="terraform CLI not installed")
def test_connections_with_differing_shapes_load_without_type_error(tmp_path):
    # Regression: "cannot find a common base type for all elements" at plan time.
    out = tmp_path / "proj"
    run(input_path=str(FIX / "connections_differing_shapes.tf"), out_dir=str(out),
        env="dev", other_envs=[])
    env_dir = out / "envs" / "dev"
    subprocess.run(["terraform", "init", "-backend=false"],
                   cwd=env_dir, check=True, capture_output=True)
    r = subprocess.run(["terraform", "plan", "-refresh=false", "-input=false"],
                       cwd=env_dir, capture_output=True, text=True,
                       env={**__import__("os").environ,
                            "TF_VAR_auth0_domain": "x.au.auth0.com",
                            "TF_VAR_auth0_client_id": "x",
                            "TF_VAR_auth0_client_secret": "x"})
    out_text = r.stdout + r.stderr
    assert "common base type" not in out_text
    assert "Invalid value for input variable" not in out_text


@pytest.mark.skipif(shutil.which("terraform") is None,
                    reason="terraform CLI not installed")
def test_extracted_action_code_reaches_terraform_unescaped(tmp_path):
    # End to end: what Terraform's file() returns for the generated action file is
    # the real JavaScript, with no doubled dollar.
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "auth0_generated.tf").write_text(
        'resource "auth0_action" "a" {\n'
        '  name    = "a"\n  runtime = "node22"\n'
        '  code    = "console.log(`user $${event.user.user_id}`);"\n}\n')
    out = tmp_path / "proj"
    run(input_path=str(raw), out_dir=str(out), env="dev", other_envs=[])
    js = out / "modules/code/actions_code/a.js"
    probe = tmp_path / "probe"
    probe.mkdir()
    (probe / "main.tf").write_text(f'output "code" {{ value = file("{js}") }}\n')
    subprocess.run(["terraform", "init"], cwd=probe, check=True, capture_output=True)
    subprocess.run(["terraform", "apply", "-auto-approve"], cwd=probe, check=True,
                   capture_output=True)
    got = subprocess.run(["terraform", "output", "-raw", "code"], cwd=probe, check=True,
                         capture_output=True, text=True).stdout
    assert got.strip() == "console.log(`user ${event.user.user_id}`);"
