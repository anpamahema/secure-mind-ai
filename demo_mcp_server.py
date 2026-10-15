"""Synthetic MCP server for local development. Never accesses real systems."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("SecureMind Synthetic Demo")

@mcp.tool()
def search_public_docs(query: str) -> dict:
    """Search a tiny synthetic documentation catalogue."""
    docs = [
        {"title":"OAuth basics","snippet":"Use authorization code flow and validate redirect URIs."},
        {"title":"Secure tool design","snippet":"Validate arguments and apply least privilege."},
        {"title":"Audit guidance","snippet":"Record security decisions without storing secrets."},
    ]
    q = query.lower()
    return {"results":[d for d in docs if q in d["title"].lower() or q in d["snippet"].lower()]}

@mcp.tool()
def get_demo_status() -> dict:
    """Return synthetic demo status."""
    return {"status":"ok","environment":"synthetic-demo","external_systems":False}

if __name__ == "__main__":
    mcp.run()
