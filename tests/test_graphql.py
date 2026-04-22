"""Tests for NetBoxRestClient.graphql() and the netbox_graphql_query MCP tool."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from netbox_mcp_server.netbox_client import NetBoxRestClient


@pytest.fixture
def client():
    return NetBoxRestClient(
        url="https://netbox.example.com/",
        token="test-token",
        verify_ssl=True,
    )


def _mock_response(status_code: int, json_body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(f"{status_code}")
    return resp


def test_graphql_url_built_from_base_without_api_prefix(client):
    assert client.graphql_url == "https://netbox.example.com/graphql/"


def test_graphql_posts_query_and_returns_data(client):
    fake = _mock_response(200, {"data": {"device_list": [{"id": "1", "name": "x"}]}})
    with patch.object(client.session, "post", return_value=fake) as mock_post:
        data = client.graphql("{ device_list { id name } }")

    assert data == {"device_list": [{"id": "1", "name": "x"}]}
    call = mock_post.call_args
    assert call.args[0] == "https://netbox.example.com/graphql/"
    assert call.kwargs["json"] == {"query": "{ device_list { id name } }"}
    assert call.kwargs["verify"] is True


def test_graphql_includes_variables_and_operation_name(client):
    fake = _mock_response(200, {"data": {"device_list": []}})
    with patch.object(client.session, "post", return_value=fake) as mock_post:
        client.graphql(
            "query Q($s: String!) { device_list(filters: {name: {exact: $s}}) { id } }",
            variables={"s": "foo"},
            operation_name="Q",
        )

    body = mock_post.call_args.kwargs["json"]
    assert body["variables"] == {"s": "foo"}
    assert body["operationName"] == "Q"


def test_graphql_raises_on_graphql_errors(client):
    fake = _mock_response(
        200,
        {"errors": [{"message": "Field 'foo' not defined"}, {"message": "boom"}]},
    )
    with patch.object(client.session, "post", return_value=fake):
        with pytest.raises(ValueError, match="Field 'foo' not defined.*boom"):
            client.graphql("{ foo }")


def test_graphql_raises_on_http_error(client):
    fake = _mock_response(500, {})
    with patch.object(client.session, "post", return_value=fake):
        with pytest.raises(requests.HTTPError):
            client.graphql("{ device_list { id } }")


def test_graphql_returns_empty_dict_when_data_missing(client):
    # NetBox should always return data, but guard against absent key.
    fake = _mock_response(200, {})
    with patch.object(client.session, "post", return_value=fake):
        assert client.graphql("{ x }") == {}


def test_graphql_respects_verify_ssl_false():
    c = NetBoxRestClient(url="https://nb.example.com", token="t", verify_ssl=False)
    fake = _mock_response(200, {"data": {}})
    with patch.object(c.session, "post", return_value=fake) as mock_post:
        c.graphql("{ x }")
    assert mock_post.call_args.kwargs["verify"] is False


def test_graphql_tool_delegates_to_client():
    from netbox_mcp_server import server

    fake_netbox = MagicMock()
    fake_netbox.graphql.return_value = {"device_list": [{"id": "1"}]}

    with patch.object(server, "netbox", fake_netbox):
        result = server.netbox_graphql_query.fn(
            query="{ device_list { id } }",
            variables={"a": 1},
            operation_name="Op",
        )

    assert result == {"device_list": [{"id": "1"}]}
    fake_netbox.graphql.assert_called_once_with(
        query="{ device_list { id } }",
        variables={"a": 1},
        operation_name="Op",
    )


def test_introspect_returns_type_info_when_found():
    from netbox_mcp_server import server

    fake_netbox = MagicMock()
    fake_netbox.graphql.return_value = {
        "__type": {
            "name": "DeviceFilter",
            "kind": "INPUT_OBJECT",
            "description": None,
            "fields": None,
            "inputFields": [
                {
                    "name": "status",
                    "description": None,
                    "type": {
                        "name": "DeviceStatusEnumFilterLookup",
                        "kind": "INPUT_OBJECT",
                        "ofType": None,
                    },
                }
            ],
            "enumValues": None,
        }
    }

    with patch.object(server, "netbox", fake_netbox):
        result = server.netbox_graphql_introspect.fn("DeviceFilter")

    assert result["name"] == "DeviceFilter"
    assert result["kind"] == "INPUT_OBJECT"
    assert result["inputFields"][0]["name"] == "status"
    call_kwargs = fake_netbox.graphql.call_args.kwargs
    assert call_kwargs["variables"] == {"name": "DeviceFilter"}
    assert "__type(name: $name)" in call_kwargs["query"]


def test_introspect_returns_not_found_marker_when_type_missing():
    from netbox_mcp_server import server

    fake_netbox = MagicMock()
    fake_netbox.graphql.return_value = {"__type": None}

    with patch.object(server, "netbox", fake_netbox):
        result = server.netbox_graphql_introspect.fn("DoesNotExist")

    assert result == {"found": False, "name": "DoesNotExist"}


# ============================================================================
# introspect_lambda_filters()
# ============================================================================


def _filter_scan_response() -> dict:
    """Simulated first-pass response: filter types with cf_*/id/status fields."""
    return {
        "devicefilter": {
            "inputFields": [
                {"name": "name", "type": {"name": "StrFilterLookup"}},
                {
                    "name": "cf_logical_cluster",
                    "type": {"name": "CFLogicalClusterLookup"},
                },
                {"name": "id", "type": {"name": "DeviceIdFilterLookup"}},
                {"name": "status", "type": {"name": "DeviceStatusFilterLookup"}},
            ]
        },
        "rackfilter": {
            "inputFields": [
                {"name": "cf_has_power", "type": {"name": "CFBooleanLookup"}},
            ]
        },
        # Non-Lambda target: no cf_* / overrides
        "locationfilter": {
            "inputFields": [
                {"name": "name", "type": {"name": "StrFilterLookup"}},
            ]
        },
        # Type doesn't exist on this instance
        "assetfilter": None,
    }


def _lookup_scan_response() -> dict:
    """Simulated second-pass response: FilterLookup shapes."""
    return {
        "l0": {  # CFBooleanLookup
            "inputFields": [{"name": "exact"}, {"name": "is_empty"}]
        },
        "l1": {  # CFLogicalClusterLookup
            "inputFields": [{"name": "slug"}, {"name": "is_empty"}]
        },
        "l2": {  # DeviceIdFilterLookup
            "inputFields": [
                {"name": "exact"},
                {"name": "in_list"},
                {"name": "is_null"},
            ]
        },
        "l3": {  # DeviceStatusFilterLookup
            "inputFields": [
                {"name": "exact"},
                {"name": "in_list"},
                {"name": "n_exact"},
                {"name": "n_in_list"},
            ]
        },
    }


def _dispatch_graphql(filter_resp: dict, lookup_resp: dict):
    """Return a side-effect fn that dispatches by query shape.

    Filter scan uses filter-type aliases (e.g. `devicefilter:`). Lookup scan
    uses positional aliases (e.g. `l0:`). Chunking may split either pass
    into multiple calls — merge responses for whichever aliases appear.
    """

    def _fn(query, *args, **kwargs):
        is_lookup_pass = any(f"l{i}:" in query for i in range(20))
        source = lookup_resp if is_lookup_pass else filter_resp
        return {k: v for k, v in source.items() if f"{k}:" in query}

    return _fn


def test_introspect_lambda_filters_builds_summary():
    from netbox_mcp_server import server

    client = MagicMock()
    client.graphql.side_effect = _dispatch_graphql(
        _filter_scan_response(), _lookup_scan_response()
    )

    summary = server.introspect_lambda_filters(client)

    assert "DeviceFilter:" in summary
    assert "RackFilter:" in summary
    # Non-Lambda LocationFilter should NOT appear (no cf_*/id/status hits)
    assert "LocationFilter:" not in summary
    # Field + lookup type + shape present
    assert "cf_logical_cluster → CFLogicalClusterLookup {slug, is_empty}" in summary
    assert "status → DeviceStatusFilterLookup {exact, in_list, n_exact, n_in_list}" in summary
    assert "id → DeviceIdFilterLookup {exact, in_list, is_null}" in summary
    assert "cf_has_power → CFBooleanLookup {exact, is_empty}" in summary


def test_introspect_lambda_filters_returns_empty_when_no_hits():
    """Non-Lambda NetBox: no cf_* fields and no FilterLookup overrides."""
    from netbox_mcp_server import server

    client = MagicMock()
    client.graphql.return_value = {
        "devicefilter": {
            "inputFields": [{"name": "name", "type": {"name": "StrFilterLookup"}}]
        }
    }

    summary = server.introspect_lambda_filters(client)

    assert summary == ""


def test_introspect_lambda_filters_graceful_fail_on_graphql_error():
    """GraphQL server error must not crash startup — just return empty summary."""
    from netbox_mcp_server import server

    client = MagicMock()
    client.graphql.side_effect = ValueError("GraphQL errors: boom")

    summary = server.introspect_lambda_filters(client)

    assert summary == ""


# ============================================================================
# _update_graphql_tool_description()
# ============================================================================


def test_update_graphql_tool_description_injects_live_schema():
    from netbox_mcp_server import server

    tool = server.mcp._tool_manager._tools.get("netbox_graphql_query")
    original = tool.description
    try:
        # Reset placeholder if a prior test consumed it
        if "[live-schema-placeholder]" not in tool.description:
            tool.description = original.replace(
                "(introspection disabled or returned no Lambda plugin fields",
                "[live-schema-placeholder]  # restored for test (",
                1,
            ) if "(introspection disabled" in original else (
                original + "\n[live-schema-placeholder]"
            )

        server._update_graphql_tool_description("DeviceFilter:\n  cf_x → CFXLookup {exact}")
        assert "DeviceFilter:\n  cf_x → CFXLookup {exact}" in tool.description
        assert "[live-schema-placeholder]" not in tool.description
    finally:
        tool.description = original


def test_update_graphql_tool_description_handles_empty_schema():
    from netbox_mcp_server import server

    tool = server.mcp._tool_manager._tools.get("netbox_graphql_query")
    original = tool.description
    try:
        if "[live-schema-placeholder]" not in tool.description:
            tool.description = original + "\n[live-schema-placeholder]"
        server._update_graphql_tool_description("")
        assert "introspection disabled or returned no Lambda plugin fields" in tool.description
        assert "[live-schema-placeholder]" not in tool.description
    finally:
        tool.description = original
