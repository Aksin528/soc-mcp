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
            resp.raise_for_status()
            return resp.json()

    @mcp.tool()
    async def splunk_notable_events(
        severity: str = "all",
        earliest: str = "-24h",
        limit: int = 10,
    ) -> dict:
        """Get Splunk ES Incident Review notable events with full enriched data.
        Severity options: informational, low, medium, high, critical, all (default: all)"""
        if severity == "all":
            query = f"search index=notable earliest={earliest} | head {limit}"
        else:
            query = f"search index=notable earliest={earliest} severity={severity} | head {limit}"
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
            resp.raise_for_status()
            return resp.json()

    @mcp.tool()
    async def splunk_list_indexes() -> dict:
        """List all available Splunk indexes."""
        async with _client() as client:
            resp = await client.get(
                f"{SPLUNK_BASE_URL}/services/data/indexes",
                headers=_headers(),
                params={"output_mode": "json", "count": 0},
            )
            resp.raise_for_status()
            return resp.json()

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
            resp.raise_for_status()
            return resp.json()

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
            resp.raise_for_status()
            return resp.json()

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
            resp.raise_for_status()
            return resp.json()
