from pattern_detector import detect_patterns
from risk_engine import calculate_risk
from policy_engine import decide

def inspect(text, profile="Enterprise", sensitivity="low", policies=None, authorized=True, tool_allowed=True):
    findings = detect_patterns(text, policies or {})
    score, severity = calculate_risk(findings, profile, sensitivity)
    decision, explanation = decide(findings, score, authorized, tool_allowed)
    return {"risk_score": score, "severity": severity, "findings": findings,
            "decision": decision, "explanation": explanation}
