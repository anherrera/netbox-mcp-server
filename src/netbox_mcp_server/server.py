import argparse
import logging
import sys
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from netbox_mcp_server.config import Settings, configure_logging
from netbox_mcp_server.netbox_client import NetBoxRestClient
from netbox_mcp_server.netbox_types import NETBOX_OBJECT_TYPES


def parse_cli_args() -> dict[str, Any]:
    """
    Parse command-line arguments for configuration overrides.

    Returns:
        dict of configuration overrides (only includes explicitly set values)
    """
    parser = argparse.ArgumentParser(
        description="NetBox MCP Server - Model Context Protocol server for NetBox",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Core NetBox settings
    parser.add_argument(
        "--netbox-url",
        type=str,
        help="Base URL of the NetBox instance (e.g., https://netbox.example.com/)",
    )
    parser.add_argument(
        "--netbox-token",
        type=str,
        help="API token for NetBox authentication",
    )

    # Transport settings
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "http"],
        help="MCP transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        type=str,
        help="Host address for HTTP server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Port for HTTP server (default: 8000)",
    )

    # Security settings
    ssl_group = parser.add_mutually_exclusive_group()
    ssl_group.add_argument(
        "--verify-ssl",
        action="store_true",
        dest="verify_ssl",
        default=None,
        help="Verify SSL certificates (default)",
    )
    ssl_group.add_argument(
        "--no-verify-ssl",
        action="store_false",
        dest="verify_ssl",
        help="Disable SSL certificate verification (not recommended)",
    )

    # Plugin discovery settings
    parser.add_argument(
        "--enable-plugin-discovery",
        action="store_true",
        default=None,
        dest="enable_plugin_discovery",
        help="Auto-discover plugin object types from NetBox at startup",
    )

    # GraphQL introspection settings
    gql_group = parser.add_mutually_exclusive_group()
    gql_group.add_argument(
        "--enable-graphql-introspection",
        action="store_true",
        default=None,
        dest="enable_graphql_introspection",
        help="Introspect Lambda plugin cf_*/FilterLookup fields at startup (default)",
    )
    gql_group.add_argument(
        "--disable-graphql-introspection",
        action="store_false",
        dest="enable_graphql_introspection",
        help="Skip GraphQL schema introspection at startup",
    )

    # Observability settings
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity level (default: INFO)",
    )

    args: argparse.Namespace = parser.parse_args()

    overlay: dict[str, Any] = {}
    if args.netbox_url is not None:
        overlay["netbox_url"] = args.netbox_url
    if args.netbox_token is not None:
        overlay["netbox_token"] = args.netbox_token
    if args.transport is not None:
        overlay["transport"] = args.transport
    if args.host is not None:
        overlay["host"] = args.host
    if args.port is not None:
        overlay["port"] = args.port
    if args.verify_ssl is not None:
        overlay["verify_ssl"] = args.verify_ssl
    if args.enable_plugin_discovery is not None:
        overlay["enable_plugin_discovery"] = args.enable_plugin_discovery
    if args.enable_graphql_introspection is not None:
        overlay["enable_graphql_introspection"] = args.enable_graphql_introspection
    if args.log_level is not None:
        overlay["log_level"] = args.log_level

    return overlay


# Default object types for global search
DEFAULT_SEARCH_TYPES = [
    "dcim.device",  # Most common search target
    "dcim.site",  # Site names frequently searched
    "ipam.ipaddress",  # IP searches very common
    "dcim.interface",  # Interface names/descriptions
    "dcim.rack",  # Rack identifiers
    "ipam.vlan",  # VLAN names/IDs
    "circuits.circuit",  # Circuit identifiers
    "virtualization.virtualmachine",  # VM names
]

mcp = FastMCP("NetBox")
netbox = None


VALID_LOOKUP_SUFFIXES = frozenset(
    {
        "n",
        "ic",
        "nic",
        "isw",
        "nisw",
        "iew",
        "niew",
        "ie",
        "nie",
        "empty",
        "regex",
        "iregex",
        "lt",
        "lte",
        "gt",
        "gte",
        "in",
    }
)

# Component endpoints where NetBox silently ignores unsupported filter parameters.
# If a filter is silently ignored, NetBox returns ALL objects — catastrophic for
# any read-then-modify/delete workflow. This map lists filters that LOOK valid
# (they pass generic syntax checks) but are NOT supported on these endpoints.
#
# The base field (before any lookup suffix) is listed. For example, "device__name"
# means device__name, device__name__ic, device__name__isw, etc. are all blocked.
#
# To filter component objects by device name, use the two-step pattern:
#   1. Query dcim.device with name filter to get the device ID
#   2. Query the component endpoint with device_id=<id>
UNSUPPORTED_COMPONENT_FILTERS: dict[str, set[str]] = {
    "dcim.interface": {
        "device__name",
        "device__name__ic",
        "device__name__isw",
        "device__name__nisw",
        "device__name__iew",
        "device__name__niew",
        "device__name__ie",
        "device__name__nie",
        "device__name__regex",
        "device__name__iregex",
    },
    "dcim.consoleport": {
        "device__name",
        "device__name__ic",
        "device__name__isw",
        "device__name__nisw",
        "device__name__iew",
        "device__name__niew",
        "device__name__ie",
        "device__name__nie",
        "device__name__regex",
        "device__name__iregex",
    },
    "dcim.consoleserverport": {
        "device__name",
        "device__name__ic",
        "device__name__isw",
        "device__name__nisw",
        "device__name__iew",
        "device__name__niew",
        "device__name__ie",
        "device__name__nie",
        "device__name__regex",
        "device__name__iregex",
    },
    "dcim.powerport": {
        "device__name",
        "device__name__ic",
        "device__name__isw",
        "device__name__nisw",
        "device__name__iew",
        "device__name__niew",
        "device__name__ie",
        "device__name__nie",
        "device__name__regex",
        "device__name__iregex",
    },
    "dcim.poweroutlet": {
        "device__name",
        "device__name__ic",
        "device__name__isw",
        "device__name__nisw",
        "device__name__iew",
        "device__name__niew",
        "device__name__ie",
        "device__name__nie",
        "device__name__regex",
        "device__name__iregex",
    },
    "dcim.frontport": {
        "device__name",
        "device__name__ic",
        "device__name__isw",
        "device__name__nisw",
        "device__name__iew",
        "device__name__niew",
        "device__name__ie",
        "device__name__nie",
        "device__name__regex",
        "device__name__iregex",
    },
    "dcim.rearport": {
        "device__name",
        "device__name__ic",
        "device__name__isw",
        "device__name__nisw",
        "device__name__iew",
        "device__name__niew",
        "device__name__ie",
        "device__name__nie",
        "device__name__regex",
        "device__name__iregex",
    },
    "dcim.devicebay": {
        "device__name",
        "device__name__ic",
        "device__name__isw",
        "device__name__nisw",
        "device__name__iew",
        "device__name__niew",
        "device__name__ie",
        "device__name__nie",
        "device__name__regex",
        "device__name__iregex",
    },
    "dcim.inventoryitem": {
        "device__name",
        "device__name__ic",
        "device__name__isw",
        "device__name__nisw",
        "device__name__iew",
        "device__name__niew",
        "device__name__ie",
        "device__name__nie",
        "device__name__regex",
        "device__name__iregex",
    },
}


def validate_filters(filters: dict, object_type: str | None = None) -> None:
    """
    Validate that filters are safe to send to the NetBox API.

    NetBox REST API silently ignores unsupported filter parameters and returns
    ALL objects instead of an error. This is catastrophic for any workflow that
    reads objects then modifies or deletes them.

    This function blocks two categories of dangerous filters:

    1. Multi-hop relationship traversal (e.g., device__site_id) — these are
       never supported on any endpoint.

    2. Known-unsupported filters on component endpoints (e.g., device__name on
       dcim/interfaces) — these look valid but are silently ignored, causing
       the API to return every object of that type.

    Args:
        filters: Dictionary of filter parameters
        object_type: Optional NetBox object type (e.g., "dcim.interface") for
                     endpoint-specific validation

    Raises:
        ValueError: If filter is unsafe (multi-hop traversal or known-unsupported
                    on the target endpoint)
    """
    # Endpoint-specific validation first (more specific error message)
    if object_type and object_type in UNSUPPORTED_COMPONENT_FILTERS:
        blocked = UNSUPPORTED_COMPONENT_FILTERS[object_type]
        for filter_name in filters:
            if filter_name in blocked:
                raise ValueError(
                    f"Unsupported filter '{filter_name}' on {object_type}: "
                    f"NetBox silently ignores this filter and returns ALL objects. "
                    f"Use the two-step pattern instead: first query dcim.device to "
                    f"get the device ID, then filter {object_type} with "
                    f"device_id=<id>."
                )

    # Generic syntax validation
    for filter_name in filters:
        # Skip special parameters
        if filter_name in ("limit", "offset", "fields", "q"):
            continue

        if "__" not in filter_name:
            continue

        parts = filter_name.split("__")

        # Allow field__suffix pattern (e.g., name__ic, id__gt)
        if len(parts) == 2 and parts[-1] in VALID_LOOKUP_SUFFIXES:
            continue
        # Block multi-hop patterns and invalid suffixes
        if len(parts) >= 2:
            raise ValueError(
                f"Invalid filter '{filter_name}': Multi-hop relationship "
                f"traversal or invalid lookup suffix not supported. "
                f"Use direct field filters like 'site_id' or two-step queries. "
                f"For component objects (interfaces, ports, bays), filter by "
                f"'device_id' instead of 'device__name'."
            )


@mcp.tool(
    description="""
    Get objects from NetBox based on their type and filters (REST).

    ⚠ PREFER GRAPHQL FOR READS. Use `netbox_graphql_query` first for almost all
    read workloads. GraphQL:
      - Enforces field selection (smaller payloads, lower token cost).
      - Supports nested filtering across relations in one round-trip
        (e.g., interface_templates by device_type.cf_lam_pn).
      - Supports FilterLookup shapes for id / status (in_list, n_in_list, ...).
      - Exposes Lambda plugin custom-field filters (`cf_*`) as first-class fields.
      - Rejects unknown filters at validation — no silent-ignore footgun.
    Use `netbox_graphql_introspect` to discover filter shapes.

    Fall back to this REST tool only when:
      - GraphQL is unavailable on the target instance.
      - Endpoint exists only on REST (no GraphQL model).
      - You explicitly need NetBox's REST-only query shape.

    SAFETY WARNING: NetBox REST API silently ignores unsupported filter parameters
    and returns ALL objects. This means a bad filter can cause you to operate on
    every object in the database instead of a filtered subset. Always use supported
    filters and verify result counts before taking action.

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        filters: dict of filters to apply to the API call based on the NetBox API filtering options

                FILTER RULES:
                Valid: Direct fields like {'site_id': 1, 'name': 'router', 'status': 'active'}
                Valid: Lookups like {'name__ic': 'switch', 'id__in': [1,2,3], 'vid__gte': 100}
                INVALID: Multi-hop like {'device__site_id': 1} - NOT supported, SILENTLY IGNORED

                COMPONENT ENDPOINTS (interfaces, ports, bays, inventory-items):
                  INVALID: {'device__name': 'foo'} or {'device__name__isw': 'foo'}
                           These are SILENTLY IGNORED and return ALL objects!
                  VALID:   Use device_id instead. Two-step pattern:
                    1. device = netbox_get_objects('dcim.device', {'name': 'foo'})
                    2. netbox_get_objects('dcim.interface', {'device_id': device['results'][0]['id']})

                Lookup suffixes: n, ic, nic, isw, nisw, iew, niew, ie, nie,
                                 empty, regex, iregex, lt, lte, gt, gte, in

                Two-step pattern for cross-relationship queries:
                  sites = netbox_get_objects('dcim.site', {'name': 'NYC'})
                  netbox_get_objects('dcim.device', {'site_id': sites[0]['id']})

        fields: Optional list of specific fields to return
                **IMPORTANT: ALWAYS USE THIS PARAMETER TO MINIMIZE TOKEN USAGE**
                Field filtering significantly reduces response payload and is critical for performance.

                - None or [] = returns all fields (NOT RECOMMENDED - use only when you need complete objects)
                - ['id', 'name'] = returns only specified fields (RECOMMENDED)

                Examples:
                - For counting: ['id'] (minimal payload)
                - For listings: ['id', 'name', 'status']
                - For IP addresses: ['address', 'dns_name', 'description']

                Uses NetBox's native field filtering via ?fields= parameter.
                **Always specify only the fields you actually need.**

        brief: returns only a minimal representation of each object in the response.
               This is useful when you need only a list of available objects without any related data.

        limit: Maximum results to return (default 5, max 100)
               Start with default, increase only if needed

        offset: Skip this many results for pagination (default 0)
                Example: offset=0 (page 1), offset=5 (page 2), offset=10 (page 3)

        ordering: Fields used to determine sort order of results.
                  Field names may be prefixed with '-' to invert the sort order.
                  Multiple fields may be specified with a list of strings.

                  Examples:
                  - 'name' (alphabetical by name)
                  - '-id' (ordered by ID descending)
                  - ['facility', '-name'] (by facility, then by name descending)
                  - None, '' or [] (default NetBox ordering)


    Returns:
        Paginated response dict with the following structure:
            - count: Total number of objects matching the query
                     ALWAYS REFER TO THIS FIELD FOR THE TOTAL NUMBER OF OBJECTS MATCHING THE QUERY
            - next: URL to next page (or null if no more pages)
                    ALWAYS REFER TO THIS FIELD FOR THE NEXT PAGE OF RESULTS
            - previous: URL to previous page (or null if on first page)
                        ALWAYS REFER TO THIS FIELD FOR THE PREVIOUS PAGE OF RESULTS
            - results: Array of objects for this page
                       ALWAYS REFER TO THIS FIELD FOR THE OBJECTS ON THIS PAGE

    ENSURE YOU ARE AWARE THE RESULTS ARE PAGINATED BEFORE PROVIDING RESPONSE TO THE USER.

    Valid object_type values:

    """
    + "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
    + """

    See NetBox API documentation for filtering options for each object type.
    """
)
def netbox_get_objects(
    object_type: str,
    filters: dict,
    fields: list[str] | None = None,
    brief: bool = False,
    limit: Annotated[int, Field(default=5, ge=1, le=100)] = 5,
    offset: Annotated[int, Field(default=0, ge=0)] = 0,
    ordering: str | list[str] | None = None,
):
    """
    Get objects from NetBox based on their type and filters
    """
    # Validate object_type exists in mapping
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    # Validate filter patterns (endpoint-aware)
    validate_filters(filters, object_type=object_type)

    # Get API endpoint and fallback from mapping
    endpoint, fallback = _get_endpoint_info(object_type)

    # Build params with pagination (parameters override filters dict)
    params = filters.copy()
    params["limit"] = limit
    params["offset"] = offset

    if fields:
        params["fields"] = ",".join(fields)

    if brief:
        params["brief"] = "1"

    if ordering:
        if isinstance(ordering, list):
            ordering = ",".join(ordering)
        if ordering.strip() != "":
            params["ordering"] = ordering

    # Make API call
    return netbox.get(endpoint, params=params, fallback_endpoint=fallback)


@mcp.tool
def netbox_get_object_by_id(
    object_type: str,
    object_id: int,
    fields: list[str] | None = None,
    brief: bool = False,
):
    """
    Get detailed information about a specific NetBox object by its ID (REST).

    ⚠ PREFER GRAPHQL FOR READS. Use `netbox_graphql_query` — e.g.
        { device(id: "123") { id name site { slug } } }
    to fetch exactly the fields you need. Fall back to this REST tool only when
    GraphQL is unavailable or the endpoint has no GraphQL equivalent.

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        object_id: The numeric ID of the object
        fields: Optional list of specific fields to return
                **IMPORTANT: ALWAYS USE THIS PARAMETER TO MINIMIZE TOKEN USAGE**
                Field filtering reduces response payload by 80-90% and is critical for performance.

                - None or [] = returns all fields (NOT RECOMMENDED - use only when you need complete objects)
                - ['id', 'name'] = returns only specified fields (RECOMMENDED)

                Examples:
                - For basic info: ['id', 'name', 'status']
                - For devices: ['id', 'name', 'status', 'site']
                - For IP addresses: ['address', 'dns_name', 'vrf', 'status']

                Uses NetBox's native field filtering via ?fields= parameter.
                **Always specify only the fields you actually need.**
        brief: returns only a minimal representation of the object in the response.
               This is useful when you need only a summary of the object without any related data.

    Returns:
        Object dict (complete or with only requested fields based on fields parameter)
    """
    # Validate object_type exists in mapping
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    # Get API endpoint and fallback from mapping
    endpoint, fallback = _get_endpoint_info(object_type)
    full_endpoint = f"{endpoint}/{object_id}"
    full_fallback = f"{fallback}/{object_id}" if fallback else None

    params = {}
    if fields:
        params["fields"] = ",".join(fields)

    if brief:
        params["brief"] = "1"

    return netbox.get(full_endpoint, params=params, fallback_endpoint=full_fallback)


@mcp.tool
def netbox_get_changelogs(filters: dict):
    """
    Get object change records (changelogs) from NetBox based on filters (REST).

    ⚠ PREFER GRAPHQL FOR READS when the instance exposes `object_change_list`.
    Fall back to this REST tool otherwise.

    Args:
        filters: dict of filters to apply to the API call based on the NetBox API filtering options

    Returns:
        Paginated response dict with the following structure:
            - count: Total number of changelog entries matching the query
                     ALWAYS REFER TO THIS FIELD FOR THE TOTAL NUMBER OF CHANGELOG ENTRIES MATCHING THE QUERY
            - next: URL to next page (or null if no more pages)
                    ALWAYS REFER TO THIS FIELD FOR THE NEXT PAGE OF RESULTS
            - previous: URL to previous page (or null if on first page)
                        ALWAYS REFER TO THIS FIELD FOR THE PREVIOUS PAGE OF RESULTS
            - results: Array of changelog entries for this page
                       ALWAYS REFER TO THIS FIELD FOR THE CHANGELOG ENTRIES ON THIS PAGE

    Filtering options include:
    - user_id: Filter by user ID who made the change
    - user: Filter by username who made the change
    - changed_object_type_id: Filter by numeric ContentType ID (e.g., 21 for dcim.device)
                              Note: This expects a numeric ID, not an object type string
    - changed_object_id: Filter by ID of the changed object
    - object_repr: Filter by object representation (usually contains object name)
    - action: Filter by action type (created, updated, deleted)
    - time_before: Filter for changes made before a given time (ISO 8601 format)
    - time_after: Filter for changes made after a given time (ISO 8601 format)
    - q: Search term to filter by object representation

    Examples:
    To find all changes made to a specific object by ID:
    {"changed_object_id": 123}

    To find changes by object name pattern:
    {"object_repr": "router-01"}

    To find all deletions in the last 24 hours:
    {"action": "delete", "time_after": "2023-01-01T00:00:00Z"}

    Each changelog entry contains:
    - id: The unique identifier of the changelog entry
    - user: The user who made the change
    - user_name: The username of the user who made the change
    - request_id: The unique identifier of the request that made the change
    - action: The type of action performed (created, updated, deleted)
    - changed_object_type: The type of object that was changed
    - changed_object_id: The ID of the object that was changed
    - object_repr: String representation of the changed object
    - object_data: The object's data after the change (null for deletions)
    - object_data_v2: Enhanced data representation
    - prechange_data: The object's data before the change (null for creations)
    - postchange_data: The object's data after the change (null for deletions)
    - time: The timestamp when the change was made
    """
    endpoint = "core/object-changes"

    # Make API call
    return netbox.get(endpoint, params=filters)


@mcp.tool(
    description="""
    Perform global search across NetBox infrastructure (REST).

    ⚠ PREFER GRAPHQL FOR READS. For targeted lookups, `netbox_graphql_query`
    with `icontains` / `in_list` filters is faster and returns exactly the
    fields requested. Reach for this fan-out tool only when you genuinely
    need the REST `q=` search behavior across many object types at once.

    Searches names, descriptions, IP addresses, serial numbers, asset tags,
    and other key fields across multiple object types.

    Args:
        query: Search term (device names, IPs, serial numbers, hostnames, site names)
               Examples: 'switch01', '192.168.1.1', 'NYC-DC1', 'SN123456'
        object_types: Limit search to specific types (optional)
                     Default: ["""
    + "', '".join(DEFAULT_SEARCH_TYPES)
    + """]
                     Examples: ['dcim.device', 'ipam.ipaddress', 'dcim.site']
        fields: Optional list of specific fields to return (reduces response size) IT IS STRONGLY RECOMMENDED TO USE THIS PARAMETER TO MINIMIZE TOKEN USAGE.
                - None or [] = returns all fields (no filtering)
                - ['id', 'name'] = returns only specified fields
                Examples: ['id', 'name', 'status'], ['address', 'dns_name']
                Uses NetBox's native field filtering via ?fields= parameter
        limit: Max results per object type (default 5, max 100)

    Returns:
        Dictionary with object_type keys and list of matching objects.
        All searched types present in result (empty list if no matches).

    Example:
        # Search for anything matching "switch"
        results = netbox_search_objects('switch')
        # Returns: {
        #   'dcim.device': [{'id': 1, 'name': 'switch-01', ...}],
        #   'dcim.site': [],
        #   ...
        # }

        # Search for IP address
        results = netbox_search_objects('192.168.1.100')
        # Returns: {
        #   'ipam.ipaddress': [{'id': 42, 'address': '192.168.1.100/24', ...}],
        #   ...
        # }

        # Limit search to specific types with field projection
        results = netbox_search_objects(
            'NYC',
            object_types=['dcim.site', 'dcim.location'],
            fields=['id', 'name', 'status']
        )
    """
)
def netbox_search_objects(
    query: str,
    object_types: list[str] | None = None,
    fields: list[str] | None = None,
    limit: Annotated[int, Field(default=5, ge=1, le=100)] = 5,
) -> dict[str, list[dict]]:
    """
    Perform global search across NetBox infrastructure.
    """
    search_types = object_types if object_types is not None else DEFAULT_SEARCH_TYPES

    # Validate all object types exist in mapping
    for obj_type in search_types:
        if obj_type not in NETBOX_OBJECT_TYPES:
            valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
            raise ValueError(f"Invalid object_type '{obj_type}'. Must be one of:\n{valid_types}")

    results = {obj_type: [] for obj_type in search_types}

    # Build results dictionary (error-resilient)
    for obj_type in search_types:
        try:
            endpoint, fallback = _get_endpoint_info(obj_type)
            response = netbox.get(
                endpoint,
                params={
                    "q": query,
                    "limit": limit,
                    "fields": ",".join(fields) if fields else None,
                },
                fallback_endpoint=fallback,
            )
            # Extract results array from paginated response
            results[obj_type] = response.get("results", [])
        except Exception:  # noqa: S112 - intentional error-resilient search
            # Continue searching other types if one fails
            # results[obj_type] already has empty list
            continue

    return results


@mcp.tool(
    description="""
    Execute a GraphQL query against NetBox's /graphql/ endpoint.

    Use GraphQL when REST filters can't express the query — especially for:
      - Nested filtering across relations (e.g., filter interface_templates by
        device_type.cf_lam_pn, or devices by role.slug + site.slug together).
      - Batch lookups by list of IDs (`id: { in_list: [...] }` on device/interface).
      - Multi-status queries without OR-chaining (`status: { in_list: [...] }`).
      - Fetching deeply nested objects in a single round-trip.
      - Queries that exercise Lambda's `lambda` plugin custom filters.

    Default to the REST tools (netbox_get_objects / _by_id / _search) for simple
    lookups; reach for this tool when you need the shapes above.

    =========================================================================
    Lambda `lambda` plugin custom filters (available on Lambda NetBox only)
    =========================================================================

    Custom-field filters exposed as first-class `cf_<name>` fields on Strawberry
    filter classes. All support lookups unless noted.

    Text CFs (lookups: exact, icontains, starts_with, in_list, is_empty):
      - cf_lam_pn              → DeviceType, ModuleType, RackType, ConsumableType
      - cf_netsuite_internal_id→ DeviceType, ModuleType, RackType, Location,
                                 ConsumableType
      - cf_cluster_name        → Rack
      - cf_scalable_unit       → Device

    Select CFs (same lookup shape as text):
      - cf_architecture        → DeviceType
      - cf_spare_type          → Device, Asset  (values: "Cold", "Validated")

    Object / multi-object CFs (nested slug/fqdn lookup):
      - cf_logical_cluster     → Device, Prefix
                                 shape: { slug: { exact|icontains|starts_with|in_list },
                                          is_empty }
      - cf_logical_clusters    → Rack, Location   (same shape as above)
      - cf_dns_zone            → Prefix
                                 shape: { fqdn: { exact|icontains|starts_with|in_list },
                                          id, id_in, is_empty }

    Rack boolean CFs (shape: { exact: true|false, is_empty: true|false }):
      cf_has_power, cf_has_clean_power, cf_has_liquid_cooling,
      cf_is_containment_complete, cf_is_edge_cabling_complete,
      cf_is_in_band_cabling_complete, cf_is_infiniband_cabling_complete,
      cf_is_liquid_cooling_operational, cf_is_maintenance_scheduled,
      cf_is_out_of_band_cabling_complete

    ID FilterLookup on DeviceFilter / InterfaceFilter (replaces bare ID scalar):
      id: { exact: "123" } | id: { in_list: ["1","2","3"] } | id: { is_null: true }

    Status FilterLookup on DeviceFilter (replaces scalar DeviceStatusEnum):
      status: { exact: STATUS_ACTIVE }
      status: { in_list: [STATUS_ACTIVE, STATUS_PLANNED] }
      status: { n_exact: STATUS_DECOMMISSIONING }
      status: { n_in_list: [STATUS_OFFLINE, STATUS_FAILED] }
      Valid enums: STATUS_OFFLINE, STATUS_ACTIVE, STATUS_PLANNED, STATUS_STAGED,
                   STATUS_FAILED, STATUS_INVENTORY, STATUS_DECOMMISSIONING

    IPAddress-by-containing-prefix (resolved server-side via net_contained):
      ip_address_list(filters: { cf_logical_cluster: { slug: { exact: "lax01-lm01" } } })
      ip_address_list(filters: { cf_dns_zone: { fqdn: { in_list: [...] } } })

    Nested filtering across relations (works with any cf_* and NetBox-native
    StrFilterLookup slugs):
      interface_template_list(filters: {
        device_type: { cf_lam_pn: { in_list: ["223-000510", "223-000053"] } }
      }) { id name }

      device_list(filters: {
        device_type: { slug: { in_list: ["sys-221he-tnr"] } }
        role:        { slug: { in_list: ["switch", "core-switch"] } }
      }) { id name }

    =========================================================================
    Performance
    =========================================================================
    - Pagination uses the `pagination` argument, NOT `limit`:
        device_list(pagination: { limit: 100, offset: 0 }) { id name }
    - Request only fields you need — NetBox serialization is heavy.
    - Cable queries benefit from the plugin's MAC-address batching
      (GenericPrefetch on cable terminations) — no caller change required.

    =========================================================================
    LIVE SCHEMA (auto-introspected at startup)
    =========================================================================
    [live-schema-placeholder]

    =========================================================================
    Gotchas
    =========================================================================
    - GraphQL rejects unknown filter fields at validation (unlike REST which
      silently ignores) — treat that as a win, read the error.
    - `is_empty: true` catches absent keys, JSON null, empty string, empty array.
    - Object/multi-object CF filters resolve slug → ID server-side; a slug that
      matches nothing returns zero rows, not an error.
    - This tool returns ONLY the `data` block. GraphQL-level errors raise
      ValueError with the concatenated messages.

    Args:
        query: GraphQL query document.
        variables: Optional dict of variables referenced by the query.
        operation_name: Optional operation name (required when the document
                        defines multiple operations).

    Returns:
        The `data` portion of the GraphQL response as a dict.

    Examples:
        # Devices in a cluster (Lambda plugin)
        netbox_graphql_query(
            query='query($s: String!) { device_list(filters: {cf_logical_cluster: {slug: {exact: $s}}}) { id name } }',
            variables={"s": "mci01-cl01"},
        )

        # Multi-status device lookup (Lambda plugin)
        netbox_graphql_query(
            query='{ device_list(filters: {status: {in_list: [STATUS_ACTIVE, STATUS_PLANNED]}}) { id name status } }',
        )

        # Device + interface batch by ID (Lambda plugin)
        netbox_graphql_query(
            query='{ device_list(filters: {id: {in_list: ["415","8746"]}}) { id name } }',
        )
    """
)
def netbox_graphql_query(
    query: str,
    variables: dict | None = None,
    operation_name: str | None = None,
) -> dict:
    """Execute a GraphQL query against NetBox."""
    return netbox.graphql(query=query, variables=variables, operation_name=operation_name)


@mcp.tool(
    description="""
    Introspect NetBox's GraphQL schema for a type name.

    Use this to discover what filter fields a given query accepts and what
    shape each filter expects — especially for Lambda plugin cf_* filters,
    FilterLookup inputs, and nested relation filters. Returns the fields of
    the named type (OBJECT, INPUT_OBJECT, ENUM) with their types.

    Typical names to introspect:
      - Query object: "Query"                   (lists all top-level queries)
      - Filter inputs: "DeviceFilter", "RackFilter", "InterfaceTemplateFilter",
                       "PrefixFilter", "IPAddressFilter", "DeviceTypeFilter"
      - Lookup inputs: "StrFilterLookup", "IntegerFilterLookup",
                       "DeviceStatusEnumFilterLookup"
      - Object types:  "DeviceType", "RackType", "InterfaceType"
                       (GraphQL types, not NetBox DeviceType model)

    Args:
        type_name: GraphQL type name (case-sensitive).

    Returns:
        Dict with keys `name`, `kind`, `description`, and one of `fields`
        (OBJECT/INTERFACE), `inputFields` (INPUT_OBJECT), or `enumValues`
        (ENUM). Returns {"found": False, "name": type_name} if the type
        does not exist.

    Example:
        # Discover DeviceFilter fields
        netbox_graphql_introspect("DeviceFilter")

        # Confirm FilterLookup shape
        netbox_graphql_introspect("StrFilterLookup")
    """
)
def netbox_graphql_introspect(type_name: str) -> dict:
    """Introspect a GraphQL type by name."""
    query = """
    query($name: String!) {
      __type(name: $name) {
        name
        kind
        description
        fields { name description type { name kind ofType { name kind } } }
        inputFields { name description type { name kind ofType { name kind } } }
        enumValues { name description }
      }
    }
    """
    data = netbox.graphql(query=query, variables={"name": type_name})
    type_info = data.get("__type")
    if type_info is None:
        return {"found": False, "name": type_name}
    return type_info


def _get_endpoint_info(object_type: str) -> tuple[str, str | None]:
    """
    Returns (endpoint, fallback_endpoint) for the given object type.

    The fallback_endpoint is used for NetBox version compatibility when
    an endpoint path has changed between versions.

    Args:
        object_type: The NetBox object type (e.g., "dcim.device")

    Returns:
        Tuple of (endpoint, fallback_endpoint). fallback_endpoint is None
        if no fallback is needed for this object type.
    """
    type_info = NETBOX_OBJECT_TYPES[object_type]
    return type_info["endpoint"], type_info.get("fallback_endpoint")


def discover_plugin_types(client: NetBoxRestClient) -> dict[str, dict[str, str]]:
    """Discover plugin object types from NetBox's object-types API.

    Queries the NetBox instance for installed plugin models that have REST API
    endpoints and returns them in the same format as NETBOX_OBJECT_TYPES.

    Args:
        client: Initialized NetBox REST API client

    Returns:
        Dict mapping type keys (e.g. "netbox_dns.zone") to endpoint info dicts.
        Returns empty dict on any error (graceful degradation).
    """
    logger = logging.getLogger(__name__)
    plugin_types: dict[str, dict[str, str]] = {}

    try:
        # Paginate through all object types
        offset = 0
        limit = 100
        while True:
            response = client.get(
                "core/object-types",
                params={"limit": limit, "offset": offset},
                fallback_endpoint="extras/object-types",  # NetBox < 4.4
            )

            results = response.get("results", [])
            for obj_type in results:
                # Only include plugin models with REST API endpoints
                if not obj_type.get("is_plugin_model", False):
                    continue

                rest_url = obj_type.get("rest_api_endpoint")
                if not rest_url:
                    continue

                app_label = obj_type.get("app_label", "")
                model = obj_type.get("model", "")
                if not app_label or not model:
                    continue

                type_key = f"{app_label}.{model}"

                # Skip if it would collide with a core type
                if type_key in NETBOX_OBJECT_TYPES:
                    logger.debug(f"Skipping plugin type '{type_key}': collides with core type")
                    continue

                # Convert REST URL to endpoint path:
                # "/api/plugins/netbox-dns/zones/" -> "plugins/netbox-dns/zones"
                endpoint = rest_url.strip("/")
                if endpoint.startswith("api/"):
                    endpoint = endpoint[4:]

                # Build a display name from the model name
                display_name = obj_type.get("display", model)

                plugin_types[type_key] = {
                    "name": display_name,
                    "endpoint": endpoint,
                }

            # Check if there are more pages
            if not response.get("next"):
                break
            offset += limit

    except Exception as e:
        logger.warning(f"Plugin discovery failed, continuing with core types only: {e}")
        return {}

    if plugin_types:
        logger.info(
            f"Discovered {len(plugin_types)} plugin object types: "
            + ", ".join(sorted(plugin_types.keys()))
        )
    else:
        logger.info("No plugin object types discovered")

    return plugin_types


def _update_tool_descriptions() -> None:
    """Update tool descriptions to reflect the current NETBOX_OBJECT_TYPES registry.

    The type list in netbox_get_objects's description is built at import time.
    After plugin discovery adds new types, this refreshes the description so
    LLMs see the full list of available types.

    Note: This accesses FastMCP's private _tool_manager API. This is acceptable
    because there is no public API for updating tool descriptions post-registration.
    """
    type_list = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
    tool = mcp._tool_manager._tools.get("netbox_get_objects")
    if tool:
        # Replace the type list portion of the description
        desc = tool.description
        marker = "Valid object_type values:"
        idx = desc.find(marker)
        if idx != -1:
            # Keep everything up to and including the marker, then append new list
            prefix = desc[: idx + len(marker)]
            suffix_marker = "See NetBox API documentation"
            suffix_idx = desc.find(suffix_marker)
            suffix = (
                f"\n\n    {suffix_marker}" + desc[suffix_idx + len(suffix_marker) :]
                if suffix_idx != -1
                else ""
            )
            tool.description = f"{prefix}\n\n{type_list}{suffix}"


# Filter types scanned for Lambda plugin overrides / cf_* additions.
# Missing types on non-Lambda NetBox resolve to null and are skipped silently.
LAMBDA_FILTER_TARGETS: tuple[str, ...] = (
    "DeviceFilter",
    "RackFilter",
    "LocationFilter",
    "PrefixFilter",
    "IPAddressFilter",
    "DeviceTypeFilter",
    "ModuleTypeFilter",
    "RackTypeFilter",
    "ConsumableTypeFilter",
    "AssetFilter",
    "InterfaceFilter",
    "InterfaceTemplateFilter",
)

# Fields treated as "Lambda-interesting" — cf_* prefix plus the id/status
# overrides the plugin swaps onto DeviceFilter/InterfaceFilter.
_LAMBDA_OVERRIDE_FIELDS = frozenset({"id", "status"})


def introspect_lambda_filters(client: NetBoxRestClient) -> str:
    """Introspect Lambda plugin cf_* / FilterLookup fields across common filter types.

    Batches one GraphQL request to scan all filter types for cf_* / overridden
    id|status fields, then a second batched request to fetch each referenced
    FilterLookup's inputFields (the actual lookup shape, e.g. exact/in_list/...).
    Returns a compact, human-readable summary for injection into the
    netbox_graphql_query tool description.

    Args:
        client: Initialized NetBox REST client (used for its graphql() method)

    Returns:
        Formatted multi-line summary, or empty string on failure / no matches.
    """
    logger = logging.getLogger(__name__)

    # NetBox/Strawberry caps __type aliases per request (10 at time of writing).
    # Keep chunks conservatively small.
    alias_chunk = 8

    def _batched(selections: list[str]) -> dict:
        """Run multiple small __type batches and merge responses."""
        merged: dict = {}
        for i in range(0, len(selections), alias_chunk):
            chunk = selections[i : i + alias_chunk]
            merged.update(client.graphql("{ " + " ".join(chunk) + " }"))
        return merged

    try:
        # Pass 1: scan filter types for cf_*/id/status fields and their lookup types
        filter_aliases = {ft: ft.lower() for ft in LAMBDA_FILTER_TARGETS}
        filter_selections = [
            f'{alias}: __type(name: "{ft}") {{ inputFields {{ name type {{ name }} }} }}'
            for ft, alias in filter_aliases.items()
        ]
        filter_data = _batched(filter_selections)

        per_filter: dict[str, list[tuple[str, str]]] = {}
        lookup_types: set[str] = set()
        for ft, alias in filter_aliases.items():
            info = filter_data.get(alias)
            if not info:
                continue
            hits: list[tuple[str, str]] = []
            for field in info.get("inputFields") or []:
                name = field["name"]
                if not (name.startswith("cf_") or name in _LAMBDA_OVERRIDE_FIELDS):
                    continue
                type_name = (field.get("type") or {}).get("name")
                if not type_name:
                    continue
                hits.append((name, type_name))
                lookup_types.add(type_name)
            if hits:
                per_filter[ft] = hits

        if not per_filter:
            return ""

        # Pass 2: resolve FilterLookup shapes in batched requests
        lookup_shapes: dict[str, list[str]] = {}
        if lookup_types:
            lookup_aliases = {lt: f"l{i}" for i, lt in enumerate(sorted(lookup_types))}
            lookup_selections = [
                f'{alias}: __type(name: "{lt}") {{ inputFields {{ name }} }}'
                for lt, alias in lookup_aliases.items()
            ]
            lookup_data = _batched(lookup_selections)
            for lt, alias in lookup_aliases.items():
                info = lookup_data.get(alias)
                if info and info.get("inputFields"):
                    lookup_shapes[lt] = [f["name"] for f in info["inputFields"]]

        # Drop id/status entries whose type is a bare scalar/enum (NetBox default,
        # NOT a Lambda plugin FilterLookup override). Keep cf_* entries always.
        cleaned: dict[str, list[tuple[str, str]]] = {}
        for ft, hits in per_filter.items():
            keep = [
                (name, lt)
                for name, lt in hits
                if name.startswith("cf_") or lt in lookup_shapes
            ]
            if keep:
                cleaned[ft] = keep

        if not cleaned:
            return ""

        # Format summary
        lines: list[str] = []
        for ft in sorted(cleaned.keys()):
            lines.append(f"{ft}:")
            for field_name, lookup_type in cleaned[ft]:
                shape = lookup_shapes.get(lookup_type)
                shape_str = " {" + ", ".join(shape) + "}" if shape else ""
                lines.append(f"  {field_name} → {lookup_type}{shape_str}")

        return "\n".join(lines)

    except Exception as e:
        logger.warning(f"GraphQL introspection failed, keeping static description: {e}")
        return ""


def _update_graphql_tool_description(live_schema: str) -> None:
    """Splice live-schema summary into the netbox_graphql_query tool description.

    The sentinel `[live-schema-placeholder]` marks the insertion point. If no
    summary was introspected, replace the sentinel (and its section header) with
    a short "(introspection disabled or returned no Lambda plugin fields)" note.
    """
    tool = mcp._tool_manager._tools.get("netbox_graphql_query")
    if not tool:
        return
    placeholder = "[live-schema-placeholder]"
    if placeholder not in tool.description:
        return
    replacement = live_schema if live_schema else (
        "(introspection disabled or returned no Lambda plugin fields — "
        "fall back to the static reference above)"
    )
    tool.description = tool.description.replace(placeholder, replacement, 1)


def main() -> None:
    """Main entry point for the MCP server."""
    global netbox

    cli_overlay: dict[str, Any] = parse_cli_args()

    try:
        settings = Settings(**cli_overlay)
    except Exception as e:
        print(f"Configuration error: {e}", file=sys.stderr)  # noqa: T201 - before logging configured
        sys.exit(1)

    configure_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    logger.info("Starting NetBox MCP Server")
    logger.info(f"Effective configuration: {settings.get_effective_config_summary()}")

    if not settings.verify_ssl:
        logger.warning(
            "SSL certificate verification is DISABLED. "
            "This is insecure and should only be used for testing."
        )

    if settings.transport == "http" and settings.host in ["0.0.0.0", "::", "[::]"]:  # noqa: S104 - checking, not binding
        logger.warning(
            f"HTTP transport is bound to {settings.host}:{settings.port}, which exposes the "
            "service to all network interfaces (IPv4/IPv6). This is insecure and should only be "
            "used for testing. Ensure this is secured with TLS/reverse proxy if exposed to network."
        )
    elif settings.transport == "http" and settings.host not in [
        "127.0.0.1",
        "localhost",
    ]:
        logger.info(
            f"HTTP transport is bound to {settings.host}:{settings.port}. "
            "Ensure this is secured with TLS/reverse proxy if exposed to network."
        )

    try:
        netbox = NetBoxRestClient(
            url=str(settings.netbox_url),
            token=settings.netbox_token.get_secret_value(),
            verify_ssl=settings.verify_ssl,
        )
        logger.debug("NetBox client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize NetBox client: {e}")
        sys.exit(1)

    if settings.enable_plugin_discovery:
        plugin_types = discover_plugin_types(netbox)
        if plugin_types:
            NETBOX_OBJECT_TYPES.update(plugin_types)
            _update_tool_descriptions()

    if settings.enable_graphql_introspection:
        live_schema = introspect_lambda_filters(netbox)
        if live_schema:
            logger.info(
                f"GraphQL introspection: discovered Lambda filters on "
                f"{live_schema.count(chr(10) + '  ')} fields across "
                f"{live_schema.count(chr(10)) - live_schema.count(chr(10) + '  ')} "
                f"filter types"
            )
        _update_graphql_tool_description(live_schema)
    else:
        _update_graphql_tool_description("")

    try:
        if settings.transport == "stdio":
            logger.info("Starting stdio transport")
            mcp.run(transport="stdio")
        elif settings.transport == "http":
            logger.info(f"Starting HTTP transport on {settings.host}:{settings.port}")
            mcp.run(transport="http", host=settings.host, port=settings.port)
    except Exception as e:
        logger.error(f"Failed to start MCP server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
