"""Resync: three-way merge of baseline / tenant / project, on real git repos."""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from auth0tf.baseline import NoBaselineError
from auth0tf.cli import main, run
from auth0tf.resync import ResyncError, _merge, _plan, format_report, resync

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
FIX = Path(__file__).parent / "fixtures"
BASE_TF = (FIX / "resync_tenant.tf").read_text()


def git(p, *a):
    return subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *a],
                          cwd=p, check=True, capture_output=True, text=True).stdout.strip()


def export(tmp_path, tf_text):
    """Raw `auth0 tf generate` input dir holding tf_text."""
    d = Path(tempfile.mkdtemp(dir=tmp_path))
    (d / "auth0_generated.tf").write_text(tf_text)
    return d


def make_project(tmp_path, commit=True):
    proj = tmp_path / "proj"
    run(str(export(tmp_path, BASE_TF)), str(proj), "dev", ["prod"])
    if commit:
        git(tmp_path, "init", "-q", str(proj))
        git(proj, "add", "-A"); git(proj, "commit", "-qm", "init")
    return proj


def do_resync(tmp_path, proj, tf_text, **kw):
    """Generate fresh output from tf_text and resync it into proj."""
    fresh = tmp_path / "fresh"; shutil.rmtree(fresh, ignore_errors=True)
    r = run(str(export(tmp_path, tf_text)), str(fresh), "dev", ["prod"], write_state=False)
    return resync(fresh, [s.key for s in r["secrets"]], proj, "dev", **kw)


def tfvars(proj):
    return proj / "envs/dev/terraform.tfvars"


# ------------------------------------------------------------------ happy paths

def test_unchanged_tenant_reports_no_changes(tmp_path):
    proj = make_project(tmp_path)
    res = do_resync(tmp_path, proj, BASE_TF)
    assert not res.changed and res.branch is None
    assert "No changes" in format_report(res, "dev")


def test_tenant_change_is_applied_and_committed_on_a_branch(tmp_path):
    proj = make_project(tmp_path)
    new = BASE_TF.replace("read only", "view things") + (
        '\nresource "auth0_role" "admin" {\n  name = "Admin"\n  description = "all"\n}\n')
    res = do_resync(tmp_path, proj, new)
    assert res.res_added == ["roles.admin"] and res.res_changed == ["roles.viewer"]
    assert res.branch == "auth0/resync" and res.commit
    assert git(proj, "branch", "--show-current") == "auth0/resync"
    txt = tfvars(proj).read_text()
    assert "view things" in txt and "admin" in txt
    assert "Nothing was pushed" in format_report(res, "dev")
    assert git(proj, "status", "--porcelain") == ""          # everything committed


def test_second_resync_of_same_tenant_is_a_noop(tmp_path):
    proj = make_project(tmp_path)
    new = BASE_TF.replace("read only", "changed")
    do_resync(tmp_path, proj, new)
    assert not do_resync(tmp_path, proj, new).changed


def test_customer_edit_elsewhere_in_the_file_is_kept(tmp_path):
    proj = make_project(tmp_path)
    txt = tfvars(proj).read_text()
    tfvars(proj).write_text("# CUSTOMER NOTE\n" + txt)
    git(proj, "commit", "-qam", "note")
    res = do_resync(tmp_path, proj, BASE_TF.replace("read only", "changed"))
    assert "envs/dev/terraform.tfvars" in res.merged and not res.conflicts
    out = tfvars(proj).read_text()
    assert "# CUSTOMER NOTE" in out and "changed" in out


def test_removed_resource_is_flagged_as_destructive(tmp_path):
    proj = make_project(tmp_path)
    res = do_resync(tmp_path, proj, re.sub(r'resource "auth0_role" "editor" \{.*?\n\}\n', "",
                                           BASE_TF, flags=re.S))
    assert res.res_removed == ["roles.editor"]
    report = format_report(res, "dev")
    assert "DESTROY" in report and "rename" in report


def test_newly_required_secret_is_reported(tmp_path):
    proj = make_project(tmp_path)
    new = BASE_TF + ('\nresource "auth0_connection" "google" {\n  name = "google"\n'
                     '  strategy = "google-oauth2"\n  options {\n    client_secret = null\n  }\n}\n')
    res = do_resync(tmp_path, proj, new)
    assert res.secrets_new == ["connections.google.client_secret"]
    assert "New secret keys required" in format_report(res, "dev")


# ------------------------------------------------------------------ conflicts

def test_same_line_edit_writes_markers_and_exits_nonzero(tmp_path):
    proj = make_project(tmp_path)
    tfvars(proj).write_text(tfvars(proj).read_text().replace("read only", "CUSTOMER"))
    git(proj, "commit", "-qam", "customer")
    res = do_resync(tmp_path, proj, BASE_TF.replace("read only", "TENANT"))
    assert len(res.conflicts) == 1 and "envs/dev/terraform.tfvars" in res.conflicts[0]
    txt = tfvars(proj).read_text()
    assert "<<<<<<< project" in txt and ">>>>>>> tenant" in txt
    assert "CUSTOMER" in txt and "TENANT" in txt
    assert res.branch == "auth0/resync"            # markers live on the review branch


def test_locally_edited_file_removed_from_tenant_is_kept(tmp_path):
    proj = make_project(tmp_path)
    (proj / "modules/roles.tf").write_text("# customised\n")
    git(proj, "commit", "-qam", "custom")
    only_app = re.sub(r'resource "auth0_role" ".*?\n\}\n', "", BASE_TF, flags=re.S)
    only_app = re.sub(r'resource "auth0_role" ".*?\n\}\n', "", only_app, flags=re.S)
    res = do_resync(tmp_path, proj, only_app)
    assert (proj / "modules/roles.tf").read_text() == "# customised\n"
    assert any("kept" in c for c in res.conflicts)


# ------------------------------------------------------------------ safety

def test_unmanaged_files_are_never_touched(tmp_path):
    proj = make_project(tmp_path)
    (proj / "envs/prod/terraform.tfvars").write_text("# prod mine\n")
    (proj / ".gitignore").write_text("mine\n")
    (proj / "NOTES.md").write_text("notes\n")
    (proj / "envs/dev/backend.tf").write_text("# my backend\n")
    git(proj, "add", "-A"); git(proj, "commit", "-qm", "mine")
    do_resync(tmp_path, proj, BASE_TF.replace("read only", "changed"))
    assert (proj / "envs/prod/terraform.tfvars").read_text() == "# prod mine\n"
    assert (proj / ".gitignore").read_text() == "mine\n"
    assert (proj / "NOTES.md").read_text() == "notes\n"
    assert (proj / "envs/dev/backend.tf").read_text() == "# my backend\n"


def test_dry_run_writes_nothing(tmp_path):
    proj = make_project(tmp_path)
    before = tfvars(proj).read_text()
    res = do_resync(tmp_path, proj, BASE_TF.replace("read only", "changed"), dry_run=True)
    assert res.res_changed == ["roles.viewer"] and res.branch is None
    assert tfvars(proj).read_text() == before
    assert git(proj, "branch", "--show-current") != "auth0/resync"


def test_refuses_without_a_baseline(tmp_path):
    proj = make_project(tmp_path)
    shutil.rmtree(proj / ".auth0tf")
    with pytest.raises(NoBaselineError):
        do_resync(tmp_path, proj, BASE_TF)


def test_refuses_wrong_env(tmp_path):
    proj = make_project(tmp_path)
    fresh = tmp_path / "f"; run(str(export(tmp_path, BASE_TF)), str(fresh), "prod", [], write_state=False)
    with pytest.raises(ResyncError, match="exported for env 'dev'"):
        resync(fresh, [], proj, "prod")


def test_refuses_outside_a_git_repo_unless_no_git(tmp_path):
    proj = make_project(tmp_path, commit=False)
    new = BASE_TF.replace("read only", "changed")
    with pytest.raises(ResyncError, match="not a git repository"):
        do_resync(tmp_path, proj, new)
    res = do_resync(tmp_path, proj, new, no_git=True)
    assert res.branch is None and "changed" in tfvars(proj).read_text()


def test_refuses_with_uncommitted_managed_changes(tmp_path):
    proj = make_project(tmp_path)
    tfvars(proj).write_text(tfvars(proj).read_text() + "# dirty\n")
    with pytest.raises(ResyncError, match="Uncommitted changes"):
        do_resync(tmp_path, proj, BASE_TF.replace("read only", "changed"))
    assert tfvars(proj).read_text().endswith("# dirty\n")     # nothing was changed


def test_branch_name_is_made_unique(tmp_path):
    proj = make_project(tmp_path)
    git(proj, "branch", "auth0/resync")
    res = do_resync(tmp_path, proj, BASE_TF.replace("read only", "changed"))
    assert res.branch == "auth0/resync-2"


# ------------------------------------------------------------------ units

def test_plan_decision_table(tmp_path):
    proj = tmp_path / "proj"; (proj / "modules").mkdir(parents=True)
    def put(name, text): (proj / "modules" / name).write_text(text)
    put("same.tf", "x"); put("takes.tf", "old"); put("gone.tf", "old")
    base = {"modules/same.tf": "x", "modules/takes.tf": "old", "modules/gone.tf": "old"}
    tenant = {"modules/same.tf": "x", "modules/takes.tf": "new", "modules/fresh.tf": "n"}
    res, writes = _plan(base, tenant, proj, "dev")
    assert res.unchanged == ["modules/same.tf"]
    assert res.updated == ["modules/takes.tf"] and writes["modules/takes.tf"] == "new"
    assert res.added == ["modules/fresh.tf"]
    assert res.deleted == ["modules/gone.tf"] and writes["modules/gone.tf"] is None


@pytest.mark.parametrize("project,expect_conflicts", [
    ("a\nb\nc\nd\n", 0),          # untouched
    ("a\nB\nc\nd\n", 1),          # same line edited both sides
    ("a\nb\nc\nD\n", 0),          # different line edited
])
def test_merge_exit_codes(project, expect_conflicts):
    _text, n = _merge(project, "a\nb\nc\nd\n", "a\nT\nc\nd\n")
    assert n == expect_conflicts


def test_cli_resync_exit_codes_and_dry_run(tmp_path, capsys):
    proj = make_project(tmp_path)
    raw = export(tmp_path, BASE_TF.replace("read only", "changed"))
    with pytest.raises(SystemExit) as e:
        main(["resync", "--input", str(raw), "--project", str(proj), "--env", "dev", "--dry-run"])
    assert e.value.code == 0
    assert "roles.viewer" in capsys.readouterr().out
    shutil.rmtree(proj / ".auth0tf")
    with pytest.raises(SystemExit) as e:
        main(["resync", "--input", str(raw), "--project", str(proj), "--env", "dev"])
    assert e.value.code == 2
