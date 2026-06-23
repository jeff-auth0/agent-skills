from pathlib import Path

from auth0tf.model import Resource, Tenant
from auth0tf.parse import parse_dir
from auth0tf.references import build_id_index, exclude_builtin_apis, rewire

FIX = Path(__file__).parent / "fixtures"


def _assoc_tenant():
    """Targets + association resources covering scalar/list/nested/identifier refs."""
    t = Tenant()
    t.add(Resource("auth0_client", "app_a", "CID_A", {"name": "App A"}))
    t.add(Resource("auth0_client", "app_b", "CID_B", {"name": "App B"}))
    t.add(Resource("auth0_connection", "db", "con_123", {"name": "db"}))
    t.add(Resource("auth0_action", "act_x", "act_uuid_1", {"name": "act-x"}))
    t.add(Resource("auth0_resource_server", "custom_api", "rs_1",
                   {"identifier": "https://api.example.com"}))
    # association resources
    t.add(Resource("auth0_client_credentials", "cc", "CID_A",
                   {"client_id": "CID_A", "authentication_method": "client_secret_post"}))
    t.add(Resource("auth0_connection_clients", "cx", "con_123",
                   {"connection_id": "con_123", "enabled_clients": ["CID_A", "CID_B"]}))
    t.add(Resource("auth0_trigger_actions", "post_login", "",
                   {"trigger": "post-login",
                    "actions": [{"display_name": "act-x", "id": "act_uuid_1"}]},
                   block_fields={"actions"}))
    t.add(Resource("auth0_resource_server_scopes", "custom_api_scopes", "",
                   {"resource_server_identifier": "https://api.example.com"}))
    return t


def test_rewire_scalar_ref_in_for_each_type():
    t = _assoc_tenant()
    rewire(t)
    cc = t.of_type("auth0_client_credentials")[0]
    assert cc.attrs["client_id_key"] == "app_a"
    assert "client_id" not in cc.attrs


def test_rewire_list_ref():
    t = _assoc_tenant()
    rewire(t)
    cx = t.of_type("auth0_connection_clients")[0]
    assert cx.attrs["connection_id_key"] == "db"
    assert cx.attrs["enabled_clients_keys"] == ["app_a", "app_b"]
    assert "enabled_clients" not in cx.attrs and "connection_id" not in cx.attrs


def test_rewire_nested_ref_replaces_inner_id_with_key():
    t = _assoc_tenant()
    rewire(t)
    ta = t.of_type("auth0_trigger_actions")[0]
    # inner id replaced with the action's logical key; block retained
    assert ta.attrs["actions"][0]["id"] == "act_x"
    assert ta.attrs["actions"][0]["display_name"] == "act-x"


def test_rewire_identifier_matched_ref():
    t = _assoc_tenant()
    rewire(t)
    rss = t.of_type("auth0_resource_server_scopes")[0]
    assert rss.attrs["resource_server_identifier_key"] == "custom_api"
    assert "resource_server_identifier" not in rss.attrs


def test_exclude_builtin_apis_drops_mgmt_and_my_account_rs_and_scopes():
    t = Tenant()
    # Management API (built-in)
    t.add(Resource("auth0_resource_server", "auth0_management_api", "rs_mgmt",
                   {"identifier": "https://t.au.auth0.com/api/v2/"}))
    t.add(Resource("auth0_resource_server_scopes", "auth0_management_api", "",
                   {"resource_server_identifier": "https://t.au.auth0.com/api/v2/",
                    "scopes": [{"name": "read:users"}, {"name": "create:clients"}]}))
    # My Account API (built-in)
    t.add(Resource("auth0_resource_server", "auth0_my_account_api", "rs_me",
                   {"identifier": "https://t.au.auth0.com/me/"}))
    t.add(Resource("auth0_resource_server_scopes", "auth0_my_account_api", "",
                   {"resource_server_identifier": "https://t.au.auth0.com/me/",
                    "scopes": [{"name": "read:me:factors"}]}))
    # custom API + its scopes must survive
    t.add(Resource("auth0_resource_server", "custom_api", "rs_custom",
                   {"identifier": "https://api.example.com"}))
    t.add(Resource("auth0_resource_server_scopes", "custom_api_scopes", "",
                   {"resource_server_identifier": "https://api.example.com",
                    "scopes": [{"name": "read:thing"}]}))

    removed = exclude_builtin_apis(t)

    assert [r.key for r in t.of_type("auth0_resource_server")] == ["custom_api"]
    assert [s.key for s in t.of_type("auth0_resource_server_scopes")] == ["custom_api_scopes"]
    # report mentions both built-in APIs (with scope counts)
    assert any("Management API" in r for r in removed)
    assert any("2 default Management API scopes" in r for r in removed)
    assert any("My Account API" in r for r in removed)
    assert any("1 default My Account API scopes" in r for r in removed)


def test_exclude_builtin_apis_noop_without_builtin():
    t = Tenant()
    t.add(Resource("auth0_resource_server", "custom_api", "rs_custom",
                   {"identifier": "https://api.example.com"}))
    removed = exclude_builtin_apis(t)
    assert removed == []
    assert [r.key for r in t.of_type("auth0_resource_server")] == ["custom_api"]


def test_build_id_index_maps_source_id_to_target():
    tenant = parse_dir(FIX / "refs_tenant.tf")
    idx = build_id_index(tenant)
    # CID_APP belongs to auth0_client "my_app" (and the grant does NOT pollute it)
    assert idx["CID_APP"] == ("auth0_client", "my_app")


def test_rewire_sets_key_field_and_drops_literal():
    tenant = parse_dir(FIX / "refs_tenant.tf")
    rewire(tenant)
    grant = tenant.of_type("auth0_client_grant")[0]
    # the literal id is dropped; a per-instance lookup key is stored instead.
    # tfvars will carry client_id_key; the module does the lookup.
    assert grant.attrs["client_id_key"] == "my_app"
    assert "client_id" not in grant.attrs


def test_rewire_leaves_unresolvable_ids_untouched():
    tenant = parse_dir(FIX / "refs_tenant.tf")
    tenant.of_type("auth0_client_grant")[0].attrs["client_id"] = "UNKNOWN_ID"
    unresolved = rewire(tenant)
    assert "UNKNOWN_ID" in unresolved
    grant = tenant.of_type("auth0_client_grant")[0]
    assert grant.attrs["client_id"] == "UNKNOWN_ID"
    assert "client_id_key" not in grant.attrs
