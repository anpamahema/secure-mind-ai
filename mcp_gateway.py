"""Enforcement boundary for tools. Demo tools are synthetic and never run arbitrary shell commands."""
import json
from database import connect
from permissions import check_tool_permission, check_resource_permission
from pattern_detector import detect_patterns
from risk_engine import calculate_risk
from policy_engine import decide

def evaluate_and_record(user, payload, policy_values):
    with connect() as c:
        tool = None
        if payload.tool_name:
            row = c.execute("SELECT * FROM tools WHERE name=?", (payload.tool_name,)).fetchone()
            tool = dict(row) if row else None
    allowed = True if not payload.tool_name else check_tool_permission(user, tool)
    resource_ok = check_resource_permission(user, payload.resource_id)
    if payload.resource_id and not resource_ok:
        allowed = False
    findings = detect_patterns(payload.text + " " + json.dumps(payload.arguments), policy_values)
    score, severity = calculate_risk(findings, payload.profile, (tool or {}).get("sensitivity","low"), payload.transaction_amount)
    needs_review = False
    if payload.transaction_amount is not None and policy_values.get("require_transaction_approval", True):
        if payload.transaction_amount >= float(policy_values.get("transaction_threshold", 10000)):
            needs_review = True
    decision, explanation = decide(findings, score, authorized=True, tool_allowed=allowed, needs_review=needs_review)
    return tool, findings, score, severity, decision, explanation

async def call_configured_mcp_tool(server_config: dict, tool_name: str, arguments: dict):
    """Optional official MCP SDK stdio client for explicitly configured commands only.
    Never pass user-controlled executable/args. Configure these values administratively.
    """
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    params = StdioServerParameters(command=server_config["command"], args=server_config.get("args", []),
                                   env=server_config.get("env"))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments)
            return result
