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
        env="dev", kv="azure", other_envs=[], cicd="none")
    env_dir = out / "envs" / "dev"
    subprocess.run(["terraform", "init", "-backend=false"],
                   cwd=env_dir, check=True, capture_output=True)
    r = subprocess.run(["terraform", "validate"],
                       cwd=env_dir, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + r.stdout
