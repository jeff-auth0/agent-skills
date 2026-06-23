from auth0tf.model import Resource, Tenant, slugify


def test_slugify_basic():
    assert slugify("My SPA App") == "my_spa_app"
    assert slugify("Admin-Portal (prod)") == "admin_portal_prod"
    assert slugify("  Trailing  ") == "trailing"


def test_slugify_collision_suffix():
    seen = set()
    a = slugify("My App", seen)
    b = slugify("My App", seen)
    assert a == "my_app"
    assert b == "my_app_2"


def test_resource_holds_attrs_and_key():
    r = Resource(
        tf_type="auth0_client",
        key="my_app",
        source_id="abc123",
        attrs={"name": "My App", "app_type": "spa"},
    )
    assert r.tf_type == "auth0_client"
    assert r.key == "my_app"
    assert r.source_id == "abc123"
    assert r.attrs["app_type"] == "spa"


def test_tenant_groups_by_type():
    t = Tenant()
    t.add(Resource("auth0_client", "a", "1", {"name": "A"}))
    t.add(Resource("auth0_client", "b", "2", {"name": "B"}))
    t.add(Resource("auth0_role", "r", "3", {"name": "R"}))
    assert set(t.types()) == {"auth0_client", "auth0_role"}
    assert len(t.of_type("auth0_client")) == 2
