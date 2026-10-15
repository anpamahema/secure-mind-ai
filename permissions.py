from fastapi import HTTPException
def check_tool_permission(user, tool):
    if not tool or not tool["enabled"]:
        return False
    # Example role gate for high-sensitivity actions; adjust to your actual application model.
    if tool["sensitivity"] == "high" and user["role"] not in ("Admin","Security Reviewer"):
        return False
    return True

def check_resource_permission(user, resource_id):
    if not resource_id:
        return True
    # Synthetic records are intentionally limited to an explicit demo namespace.
    return resource_id.startswith("demo:")
