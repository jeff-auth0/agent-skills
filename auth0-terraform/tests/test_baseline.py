import json
from pathlib import Path

import pytest

from auth0tf.baseline import (
    NoBaselineError, collect_managed, is_managed, read_baseline, read_state, write_baseline)
from auth0tf.cli import run

FIX = Path(__file__).parent / "fixtures"


def test_only_resync_owned_paths_are_managed():
    assert is_managed("modules/roles.tf", "dev")
    assert is_managed("envs/dev/terraform.tfvars", "dev")
    assert is_managed("README.md", "dev")
    for rel in ("envs/prod/terraform.tfvars", ".gitignore", "PROJECT_CONTEXT.md",
                "CLAUDE.md", "NOTES.md", ".auth0tf/state.json"):
        assert not is_managed(rel, "dev"), rel


def test_transform_writes_baseline_equal_to_generated_files(tmp_path):
    out = tmp_path / "p"
    run(str(FIX / "resync_tenant.tf"), str(out), "dev", ["prod"])
    state = read_state(out)
    assert state["env"] == "dev" and state["other_envs"] == ["prod"]
    generated = collect_managed(out, "dev")
    assert generated and read_baseline(out, "dev") == generated
    assert "envs/prod/terraform.tfvars" not in generated      # other envs not stored


def test_baseline_is_not_part_of_the_managed_set(tmp_path):
    out = tmp_path / "p"
    run(str(FIX / "resync_tenant.tf"), str(out), "dev", [])
    assert not any(k.startswith(".auth0tf") for k in collect_managed(out, "dev"))


def test_missing_baseline_is_reported_not_guessed(tmp_path):
    with pytest.raises(NoBaselineError, match="Re-export"):
        read_state(tmp_path)
    (tmp_path / ".auth0tf").mkdir()
    with pytest.raises(NoBaselineError):
        read_baseline(tmp_path, "dev")


def test_write_baseline_replaces_previous_snapshot(tmp_path):
    gen = tmp_path / "gen"; (gen / "modules").mkdir(parents=True)
    (gen / "modules" / "a.tf").write_text("a")
    proj = tmp_path / "proj"; proj.mkdir()
    write_baseline(proj, gen, "dev", [], ["k1"])
    (gen / "modules" / "a.tf").unlink(); (gen / "modules" / "b.tf").write_text("b")
    write_baseline(proj, gen, "dev", [], ["k2"])
    assert set(read_baseline(proj, "dev")) == {"modules/b.tf"}
    assert json.loads((proj / ".auth0tf/state.json").read_text())["secret_keys"] == ["k2"]
