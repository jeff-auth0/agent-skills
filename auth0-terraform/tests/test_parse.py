import json
from pathlib import Path

from auth0tf.parse import _eval_jsonencode, parse_dir

FIX = Path(__file__).parent / "fixtures"


def test_parse_groups_resources():
    tenant = parse_dir(FIX / "simple_tenant.tf")
    assert set(tenant.types()) == {"auth0_client", "auth0_role"}
    clients = tenant.of_type("auth0_client")
    assert {c.key for c in clients} == {"my_app", "admin"}


def test_parse_ignores_import_blocks():
    tenant = parse_dir(FIX / "simple_tenant.tf")
    # import blocks must not become resources
    assert all(r.tf_type.startswith("auth0_") for r in tenant.resources)
    assert len(tenant.resources) == 3


def test_parse_keeps_attrs():
    tenant = parse_dir(FIX / "simple_tenant.tf")
    app = next(c for c in tenant.of_type("auth0_client") if c.key == "my_app")
    assert app.attrs["app_type"] == "spa"
    assert app.attrs["name"] == "My App"


def test_eval_jsonencode_unescapes_values_and_unquotes_keys():
    # hcl2 leaves inner HCL escapes (\n, \") intact and quoted map keys quoted;
    # _eval_jsonencode must unescape leaf strings exactly once and strip quotes
    # from keys, or the resulting JSON is double-escaped / has dirty keys.
    expr = (
        'jsonencode({"signup-id" = {description = "Sign up for an account.\\n'
        'Please continue.", title = "Create your \\"account\\""}})'
    )
    result = _eval_jsonencode(expr)
    assert json.loads(result) == {
        "signup-id": {
            "description": "Sign up for an account.\nPlease continue.",
            "title": 'Create your "account"',
        }
    }
    # no literal backslash-n / backslash-quote survives, and no dirty keys
    assert "\\\\n" not in result
    assert '\\"signup-id\\"' not in result


def test_parse_prompt_custom_text_body_is_clean_json():
    tenant = parse_dir(FIX / "prompt_custom_text_tenant.tf")
    resource = tenant.of_type("auth0_prompt_custom_text")[0]
    body = json.loads(resource.attrs["body"])
    assert body == {
        "signup-id": {
            "description": "Sign up for an account.\nPlease continue.",
            "title": 'Create your "account"',
        }
    }
