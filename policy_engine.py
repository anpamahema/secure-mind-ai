def decide(findings, risk_score, authorized=True, tool_allowed=True, needs_review=False):
    """Apply conservative, deterministic decision precedence for the demo gateway.

    Authorization/tool permissions are checked first. Explicit DENY rules then take
    precedence over BLOCK, followed by REVIEW. A risk score alone never grants access.
    """
    if not authorized or not tool_allowed:
        return "DENY", "Authentication, authorization, resource ownership, or tool permission check failed."
    if any(f.get("recommended_action") == "DENY" for f in findings):
        return "DENY", "A rule detected potentially unauthorized access to a protected resource."
    if any(f.get("recommended_action") == "BLOCK" for f in findings):
        return "BLOCK", "A mandatory security rule prohibits this request."
    if needs_review or any(f.get("recommended_action") == "REVIEW" for f in findings):
        return "REVIEW", "Human review is required by the applicable policy."
    if risk_score >= 80:
        return "REVIEW", "High risk requires human review."
    return "ALLOW", "No configured rule matched; this is not proof of real-world authorization."
