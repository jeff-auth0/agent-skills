
import json

from auth0tf.extract import (
    extract_branding_templates,
    extract_code,
    extract_email_bodies,
    extract_form_bodies,
    scaffold_action_secrets,
)
from auth0tf.model import Resource, Tenant


def test_extract_action_code_writes_file_and_replaces_attr(tmp_path):
    t = Tenant()
    t.add(Resource("auth0_action", "Post Login", "a1",
                   {"name": "Post Login", "code": "exports.onExecute = () => {};"}))
    extract_code(t, tmp_path)
    js = tmp_path / "code" / "actions_code" / "Post Login.js"
    assert js.read_text() == "exports.onExecute = () => {};"
    action = t.of_type("auth0_action")[0]
    # Stored ref is for_each-compatible (same expression for every instance),
    # while the file itself is written per-action by name.
    assert action.attrs["code"] == {
        "__ref__": 'file("${path.module}/code/actions_code/${each.value.name}.js")'
    }


def test_extract_form_bodies_unescapes_and_writes_valid_json(tmp_path):
    # python-hcl2 leaves inner \" escapes in the body string; extract_form_bodies
    # must unwrap them and write VALID JSON to a file keyed by resource.key,
    # replacing the attr with a concrete file() reference (no each.value).
    escaped_body = '{\\"coordinates\\":{\\"x\\":-476},\\"next_node\\":\\"step_RHXd\\"}'
    t = Tenant()
    t.add(Resource("auth0_form", "mfa_enrollement", "",
                   {"name": "mfa-enrollement", "start": escaped_body}))
    extract_form_bodies(t, tmp_path)
    written = (tmp_path / "forms" / "mfa_enrollement_start.json").read_text()
    # file content is valid, parseable JSON (no stray backslashes)
    assert json.loads(written) == {"coordinates": {"x": -476}, "next_node": "step_RHXd"}
    # attr replaced with a concrete file() ref (literal block, not for_each)
    form = t.of_type("auth0_form")[0]
    assert form.attrs["start"] == {
        "__ref__": 'file("${path.module}/forms/mfa_enrollement_start.json")'
    }


def test_extract_email_bodies_to_shared_files(tmp_path):
    # email template bodies are env-invariant; they must be written to
    # code/email_templates/<template>.liquid (HCL-unescaped) and the body attr
    # replaced with a for_each-compatible file() ref so it leaves tfvars.
    escaped = '<html dir=\\"ltr\\">\\n  <body>Hi</body>\\n</html>'
    t = Tenant()
    t.add(Resource("auth0_email_template", "verify_email", "",
                   {"template": "verify_email", "syntax": "liquid",
                    "enabled": True, "body": escaped}))
    extract_email_bodies(t, tmp_path)
    written = (tmp_path / "code" / "email_templates" / "verify_email.liquid").read_text()
    # real quotes/newlines, no surviving HCL escapes
    assert written == '<html dir="ltr">\n  <body>Hi</body>\n</html>'
    tmpl = t.of_type("auth0_email_template")[0]
    assert tmpl.attrs["body"] == {
        "__ref__": 'file("${path.module}/code/email_templates/${each.value.template}.liquid")'
    }


def test_extract_branding_universal_login_template(tmp_path):
    # the universal_login body (nested block field) is written to a file,
    # HCL-unescaped, and replaced with a for_each-compatible file() ref.
    escaped = '<!DOCTYPE html>\\n<html lang=\\"en\\">\\n</html>'
    t = Tenant()
    t.add(Resource("auth0_branding", "branding", "",
                   {"logo_url": "x", "universal_login": [{"body": escaped}]},
                   block_fields={"universal_login"}))
    extract_branding_templates(t, tmp_path)
    written = (tmp_path / "branding" / "branding_universal_login.html").read_text()
    assert written == '<!DOCTYPE html>\n<html lang="en">\n</html>'  # unescaped
    block = t.of_type("auth0_branding")[0].attrs["universal_login"][0]
    assert block["body"] == {
        "__ref__": 'file("${path.module}/branding/${each.key}_universal_login.html")'
    }


def test_extract_action_code_unescapes_to_real_source(tmp_path):
    # source code arrives HCL-escaped (literal \n, \", \uXXXX); the written .js
    # must be real multi-line source, not a single escaped line.
    escaped = 'exports.onExecute = async (event, api) => {\\n  if (x \\u003c 1) {\\n    console.log(\\"hi\\");\\n  }\\n};'
    t = Tenant()
    t.add(Resource("auth0_action", "Post Login", "a1",
                   {"name": "Post Login", "code": escaped}))
    extract_code(t, tmp_path)
    js = (tmp_path / "code" / "actions_code" / "Post Login.js").read_text()
    assert "\n" in js and "\\n" not in js          # real newlines, no literal \n
    assert 'console.log("hi");' in js              # quotes unescaped
    assert "if (x < 1)" in js                      # < -> <
    assert js.count("\n") >= 4                     # genuinely multi-line


def test_scaffold_action_secrets_records_names_only():
    # every secret name the code reads is listed (sorted, de-duplicated); no
    # values, no guess at which names are "really" sensitive.
    code = ("exports.onExecutePostLogin = async (event, api) => {\n"
            "  const url = event.secrets.TOYOTA_LOGO_URL;\n"
            "  const base = secrets.IG_BASE_URL;\n"
            "  const again = secrets.IG_BASE_URL;\n"
            "  const sec = secrets.INTEGRATION_GATEWAY_CLIENT_SECRET;\n"
            "};")
    t = Tenant()
    t.add(Resource("auth0_action", "a", "1", {"name": "a", "code": code}))
    scaffold_action_secrets(t)
    a = t.of_type("auth0_action")[0]
    assert a.attrs["secret_names"] == [
        "IG_BASE_URL", "INTEGRATION_GATEWAY_CLIENT_SECRET", "TOYOTA_LOGO_URL"]
    assert "secrets" not in a.attrs and "kv_secrets" not in a.attrs


def test_scaffold_action_secrets_routes_form_id_to_reference():
    # a *_FORM_ID secret resolves to the best-matching auth0_form reference and is
    # NOT a customer secret.
    t = Tenant()
    t.add(Resource("auth0_form", "form_profile_enrollement", "", {"name": "f"}))
    t.add(Resource("auth0_form", "mfa_enrollement", "", {"name": "m"}))
    code = "api.prompt.render(event.secrets.PROGRESSIVE_PROFILING_FORM_ID, {});"
    t.add(Resource("auth0_action", "progressive_profiling", "1",
                   {"name": "progressive-profiling", "code": code}))
    scaffold_action_secrets(t)
    a = t.of_type("auth0_action")[0]
    assert a.attrs["ref_secrets"] == {
        "PROGRESSIVE_PROFILING_FORM_ID": "auth0_form.form_profile_enrollement.id"
    }
    assert "PROGRESSIVE_PROFILING_FORM_ID" not in a.attrs["secret_names"]


def test_scaffold_action_secrets_noop_without_refs():
    t = Tenant()
    t.add(Resource("auth0_action", "a", "1",
                   {"name": "a", "code": "exports.onExecutePostLogin = () => {};"}))
    scaffold_action_secrets(t)
    a = t.of_type("auth0_action")[0]
    assert "secret_names" not in a.attrs and "ref_secrets" not in a.attrs


def test_form_flow_body_cross_refs_wrapped_with_replace(tmp_path):
    # ids of other resources embedded in a form/flow body are swapped for live
    # references at apply time via replace(), so the body is tenant-agnostic.
    t = Tenant()
    t.add(Resource("auth0_flow", "flow_send_sms_otp", "af_SEND", {"name": "send"}))
    t.add(Resource("auth0_flow_vault_connection", "ig_m2m_token", "ac_VAULT",
                   {"name": "ig"}))
    t.add(Resource("auth0_form", "f", "ap_FORM",
                   {"name": "f",
                    "nodes": '[{"config":{"flow_id":"af_SEND"}}]'}))
    t.add(Resource("auth0_flow", "validate", "af_VALIDATE",
                   {"name": "v",
                    "actions": '[{"connection_id":"ac_VAULT"}]'}))
    extract_form_bodies(t, tmp_path)

    form_expr = t.of_type("auth0_form")[0].attrs["nodes"]["__ref__"]
    assert 'file("${path.module}/forms/f_nodes.json")' in form_expr
    assert '"af_SEND", auth0_flow.flow_send_sms_otp.id' in form_expr
    # the written file still holds the source id (replace runs at apply time)
    assert "af_SEND" in (tmp_path / "forms" / "f_nodes.json").read_text()

    flow_expr = [r for r in t.of_type("auth0_flow")
                 if r.key == "validate"][0].attrs["actions"]["__ref__"]
    assert ('"ac_VAULT", auth0_flow_vault_connection.this["ig_m2m_token"].id'
            in flow_expr)


def test_extract_db_scripts_unescapes_in_place(tmp_path):
    # `options` is an HCL block, so hcl2 parses it as a single-item list of
    # dicts, not a plain dict — and the real attribute is snake_case
    # `custom_scripts`, not `customScripts`. Bodies arrive HCL-escaped and must
    # be unescaped IN PLACE (not extracted to files, unlike action code).
    t = Tenant()
    t.add(Resource("auth0_connection", "my_db", "c1", {
        "name": "my-db",
        "options": [{
            "custom_scripts": {
                "login": "function login(user, callback) {\\n  callback(null, user);\\n}",
                "get_user": "function get_user(email, callback) {}",
            },
        }],
    }, block_fields={"options"}))
    extract_code(t, tmp_path)
    conn = t.of_type("auth0_connection")[0]
    cs = conn.attrs["options"][0]["custom_scripts"]
    assert cs["login"] == "function login(user, callback) {\n  callback(null, user);\n}"
    assert "\\n" not in cs["login"]
    assert cs["get_user"] == "function get_user(email, callback) {}"
    # no files written for connection scripts
    assert not (tmp_path / "scripts").exists()


def test_unescape_prompt_custom_text_decodes_and_pretty_prints():
    from auth0tf.extract import unescape_prompt_custom_text
    t = Tenant()
    t.add(Resource("auth0_prompt_custom_text", "en_login", "",
                   {"prompt": "login", "language": "en",
                    "body": '{\\n    \\"login\\": {\\"title\\": \\"Log in to $${co}\\"}\\n}'}))
    t.add(Resource("auth0_prompt_custom_text", "en_signup", "", {"body": "{}"}))
    t.add(Resource("auth0_prompt_custom_text", "weird", "", {"body": "not json \\\\n"}))
    unescape_prompt_custom_text(t)
    login, signup, weird = t.of_type("auth0_prompt_custom_text")
    assert "\\n" not in login.attrs["body"]       # no literal backslash-n left
    assert '\\"' not in login.attrs["body"]       # no literal backslash-quote left
    assert '"title": "Log in to $${co}"' in login.attrs["body"]   # $$ untouched
    assert login.attrs["body"].count("\n") >= 3   # real newlines: multi-line
    assert signup.attrs["body"] == "{}"
    assert weird.attrs["body"] == "not json \\n"              # non-JSON: unescaped only


def test_extracted_action_code_resolves_hcl_template_escapes(tmp_path):
    # The Auth0 CLI exports JS `${x}` as `$${x}` (HCL escape). The action file is read
    # with file(), which does not unescape, so it must be resolved when written.
    from auth0tf.extract import extract_code
    t = Tenant()
    code = "logger.info(`user $${event.user.user_id} 100%%{ok} real: ${kept}`);"
    t.add(Resource("auth0_action", "a", "1", {"name": "a", "code": code}))
    extract_code(t, tmp_path)
    js = (tmp_path / "code/actions_code/a.js").read_text()
    assert "`user ${event.user.user_id} 100%{ok}" in js
    assert "$${" not in js and "%%{" not in js


def test_template_unescape_helper():
    from auth0tf.hclstr import hcl_template_unescape as u
    assert u("a $${b} %%{c}") == "a ${b} %{c}"
    assert u("no escapes ${x}") == "no escapes ${x}"      # a single $ is left alone
    assert u("$$${x}") == "$${x}"                          # same left-to-right result as HCL
    assert u("plain") == "plain"


def test_other_extracted_bodies_resolve_escapes_too(tmp_path):
    from auth0tf.extract import extract_email_bodies
    t = Tenant()
    t.add(Resource("auth0_email_template", "v", "", {"template": "verify", "body": "Hi $${user.name}"}))
    extract_email_bodies(t, tmp_path)
    assert (tmp_path / "code/email_templates/verify.liquid").read_text() == "Hi ${user.name}"
