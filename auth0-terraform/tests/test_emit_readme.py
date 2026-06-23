from pathlib import Path

from auth0tf.emit_readme import emit_readme


def test_readme_lists_counts_and_env_instructions(tmp_path):
    emit_readme(
        tmp_path,
        counts={"auth0_client": 2, "auth0_role": 1},
        envs=["dev", "staging"],
        kv="azure",
        unresolved=["WEIRD_ID"],
    )
    txt = (tmp_path / "README.md").read_text()
    assert "auth0_client" in txt and "2" in txt
    assert "terraform init" in txt
    assert "Key Vault" in txt
    assert "WEIRD_ID" in txt  # flagged for manual review
