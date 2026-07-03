"""Splunk tools for SOC MCP server."""

import os
import httpx


SPLUNK_BASE_URL = os.environ.get("SPLUNK_BASE_URL", "https://localhost:8089")
SPLUNK_TOKEN = os.environ.get("SPLUNK_TOKEN", "")
SPLUNK_VERIFY_SSL = os.environ.get("SPLUNK_VERIFY_SSL", "true").lower() == "true"


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=SPLUNK_VERIFY_SSL, follow_redirects=True)

def _headers() -> dict:
    return {"Authorization": f"Bearer {SPLUNK_TOKEN}"}


def _handle_response(resp: httpx.Response) -> dict:
    """Raise with Splunk's own diagnostic message attached, instead of a generic httpx error."""
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        try:
            detail = resp.json().get("messages", resp.text)
        except Exception:
            detail = resp.text
        raise httpx.HTTPStatusError(
            f"{e}\nSplunk response: {detail}", request=e.request, response=e.response
        ) from None
    return resp.json()


# Full Splunk ES "Incident Review - Main" enrichment pipeline (from savedsearches.conf),
# with the dashboard's $token$ filter placeholders removed since they're blank by default.
# Requires the SplunkEnterpriseSecuritySuite app namespace to resolve these macros.
_ES_NOTABLE_ENRICHMENT = (
    "| eval `get_event_id_meval`,rule_id=event_id "
    "| dedup rule_id "
    "| fields - host_* "
    "| tags outputfield=tag "
    "| `mvappend_field(tag,orig_tag)` "
    "| `notable_xref_lookup` "
    "| `get_correlations_performant` "
    "| `get_current_status` "
    "| `get_owner` "
    "| `get_urgency` "
    "| typer "
    "| tags outputfield=tag "
    "| `mvappend_field(tag,orig_tag)` "
    "| `suppression_extract` "
    "| search NOT suppression=* "
    "| `risk_correlation` "
    "| `get_mitre_annotations` "
    "| `get_notable_type` "
    "| `get_orig_source` "
    "| `add_normalized_risk_object`"
)

ES_APP_SEARCH_URL_TMPL = "{base}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/search/jobs"


def register_splunk_tools(mcp):

    @mcp.tool()
    async def splunk_search(
        query: str,
        earliest: str = "-1h",
        latest: str = "now",
        limit: int = 100,
    ) -> dict:
        """Run a SPL search query on Splunk. Query must start with 'search'.
        Example: search index=main EventCode=4625 | head 50"""
        if not query.strip().startswith("search "):
            query = "search " + query
        async with _client() as client:
            resp = await client.post(
                f"{SPLUNK_BASE_URL}/services/search/jobs",
                headers=_headers(),
                data={
                    "search": query,
                    "earliest_time": earliest,
                    "latest_time": latest,
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                    "max_count": limit,
                    "count": 0,
                },
            )
            return _handle_response(resp)

    @mcp.tool()
    async def splunk_notable_events(
        severity: str = "all",
        earliest: str = "-24h",
        limit: int = 10,
    ) -> dict:
        """Get Splunk ES Incident Review notable events with full enriched data
        (owner, status, disposition, drilldown searches, MITRE ATT&CK, risk scores).
        Severity options: informational, low, medium, high, critical, all (default: all)"""
        query = f"search `get_notable_index` earliest={earliest} {_ES_NOTABLE_ENRICHMENT}"
        if severity != "all":
            query += f" | search severity={severity}"
        query += f" | head {limit}"
        async with _client() as client:
            resp = await client.post(
                ES_APP_SEARCH_URL_TMPL.format(base=SPLUNK_BASE_URL),
                headers=_headers(),
                data={
                    "search": query,
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                    "count": 0,
                },
            )
            return _handle_response(resp)

    @mcp.tool()
    async def splunk_list_indexes() -> dict:
        """List all available Splunk indexes."""
        async with _client() as client:
            resp = await client.get(
                f"{SPLUNK_BASE_URL}/services/data/indexes",
                headers=_headers(),
                params={"output_mode": "json", "count": 0},
            )
            return _handle_response(resp)

    @mcp.tool()
    async def splunk_list_sourcetypes(index: str = "main") -> dict:
        """List sourcetypes available in a Splunk index."""
        query = f"search index={index} | stats count by sourcetype | sort -count"
        async with _client() as client:
            resp = await client.post(
                f"{SPLUNK_BASE_URL}/services/search/jobs",
                headers=_headers(),
                data={
                    "search": query,
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                    "count": 0,
                },
            )
            return _handle_response(resp)

    @mcp.tool()
    async def splunk_search_by_ip(
        ip: str,
        earliest: str = "-24h",
        limit: int = 100,
    ) -> dict:
        """Search all Splunk events related to a specific IP address."""
        query = f"search (src_ip={ip} OR dest_ip={ip} OR src={ip} OR dest={ip}) earliest={earliest} | head {limit}"
        async with _client() as client:
            resp = await client.post(
                f"{SPLUNK_BASE_URL}/services/search/jobs",
                headers=_headers(),
                data={
                    "search": query,
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                    "count": 0,
                },
            )
            return _handle_response(resp)

    @mcp.tool()
    async def splunk_search_by_user(
        username: str,
        earliest: str = "-24h",
        limit: int = 100,
    ) -> dict:
        """Search all Splunk events related to a specific username."""
        query = f"search (user={username} OR src_user={username} OR User={username}) earliest={earliest} | head {limit}"
        async with _client() as client:
            resp = await client.post(
                f"{SPLUNK_BASE_URL}/services/search/jobs",
                headers=_headers(),
                data={
                    "search": query,
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                    "count": 0,
                },
            )
            return _handle_response(resp)
