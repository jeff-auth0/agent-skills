from pathlib import Path

from auth0tf.parse import parse_dir

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
