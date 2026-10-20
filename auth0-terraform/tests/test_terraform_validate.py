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
