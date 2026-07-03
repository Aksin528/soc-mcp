"""SOC MCP Server — Splunk, Wazuh, Cortex XDR tools for AI agents."""

from fastmcp import FastMCP
from tools.splunk import register_splunk_tools
from tools.ip_geolocation import register_ip_geolocation_tools

# Gelecekde elave edilecek:
# from tools.wazuh import register_wazuh_tools
# from tools.cortex import register_cortex_tools

mcp = FastMCP(
    name="soc-mcp",
    instructions="SOC analyst MCP server. Use these tools to investigate security alerts, search logs, and triage incidents.",
)

register_splunk_tools(mcp)
register_ip_geolocation_tools(mcp)
# register_wazuh_tools(mcp)
# register_cortex_tools(mcp)

if __name__ == "__main__":
    import os
    host = os.environ.get("MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MCP_PORT", "8100"))
    mcp.run(transport="http", host=host, port=port)
