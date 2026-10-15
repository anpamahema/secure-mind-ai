import re
from typing import Any

RULES = [
    # Cross-domain controls: apply to enterprise, healthcare, finance, HR, cloud,
    # e-commerce, education, and other MCP-connected workflows.
    ("AUTH-001", "Explicitly unauthorized access to another person's or tenant's data", "critical",
     r"\b(?:access|retrieve|read|view|download|export|open|query|modify|delete)\b.{0,120}\b(?:another|other|someone else's|different|neighboring)\b.{0,100}\b(?:user|person|customer|patient|employee|tenant|organization|client|student|account|workspace|record|file|database|profile|medical|payroll|document|resource)\b.{0,100}\b(?:without|unauthorized|unauthorised|no)\s+(?:proper\s+)?(?:authorization|authorisation|permission|consent|access rights)\b|\b(?:without|unauthorized|unauthorised)\s+(?:proper\s+)?(?:authorization|authorisation|permission|consent)\b.{0,120}\b(?:another|other|user|person|customer|patient|employee|tenant|organization|client|student|account|record|file|database|profile|resource)\b",
     "DENY", "Request explicitly describes access without authorization across a protected resource."),
    ("SECRET-001", "Credential, token, or secret extraction", "critical",
     r"\b(?:steal|exfiltrate|dump|reveal|extract|collect|return|print|show|(?<!not )expose|harvest)\b.{0,120}\b(?:passwords?|passcodes?|api\s*keys?|access tokens?|refresh tokens?|session cookies?|private keys?|secret keys?|credentials?|one[- ]time passwords?|\botps?\b|security answers?|recovery codes?|signing keys?)\b|\b(?:passwords?|passcodes?|api\s*keys?|access tokens?|refresh tokens?|session cookies?|private keys?|secret keys?|credentials?|one[- ]time passwords?|\botps?\b|security answers?|recovery codes?|signing keys?)\b.{0,60}\b(?:retrieve|reveal|dump|expose|steal|extract|exfiltrate)\b|\b(?:dump|exfiltrate|print|reveal|expose)\b.{0,80}\b(?:all\s+)?secrets\b",
     "BLOCK", "Request attempts to expose authentication credentials or system secrets."),
    ("INJ-001","Prompt injection / instruction override","critical",
     r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions|override\s+(all\s+)?safety|reveal\s+(the\s+)?system prompt|bypass\s+(the\s+)?(security|safety|policy|approval)",
     "BLOCK","Instruction override or security-bypass language detected."),
    ("PRIV-001","Privilege escalation or access-control bypass","critical",
     r"\b(?:make me admin|grant (?:me )?(?:admin|superuser|root)|disable access control|bypass (?:approval|authentication|authorization|access control)|escalate privileges|impersonate (?:the )?(?:admin|administrator|another user))\b",
     "BLOCK","Attempt to bypass authorization or elevate privileges."),
    ("DESTRUCT-001", "Potentially destructive or irreversible operation", "high",
     r"\b(?:permanently delete|wipe|destroy|drop database|erase all|purge all|shut down production|disable backups|delete all backups|revoke all users)\b",
     "REVIEW", "Potentially destructive operation requires explicit authorization and human review."),
    ("DATA-001","Bulk data extraction","high",
     r"\b(?:export|download|dump|copy|extract|retrieve)\b.{0,60}\b(?:all|entire|every|bulk|full database|all records|all users|all customers|all patients|all employees)\b|\bselect\s+\*\b",
     "REVIEW","Potential bulk data extraction requires purpose, scope, and permission checks."),
    ("HEALTH-001", "Sensitive health information disclosure", "high",
     r"\b(?:expose|publish|export|send|reveal|retrieve|download)\b.{0,100}\b(?:patient records?|medical records?|diagnoses|prescriptions|lab results|health records?|protected health information|phi)\b.{0,100}\b(?:all|another|without|unauthorized|public|external|unapproved)\b|\b(?:patient|medical|health) records?\b.{0,80}\bwithout\s+(?:authorization|permission|consent)\b",
     "REVIEW", "Sensitive health data handling requires verified purpose and authorization."),
    ("CLOUD-001", "Cloud infrastructure or production secret access", "high",
     r"\b(?:retrieve|read|download|expose|dump|list)\b.{0,100}\b(?:production secrets?|cloud credentials?|cloud metadata|environment variables?|\.env file|private keys?|secret manager|vault secrets?)\b",
     "REVIEW", "Sensitive infrastructure access requires explicit tool and resource permissions."),
    # Banking-specific controls. These are deterministic demo heuristics, not a substitute
    # for identity, account-ownership, transaction-limit, and fraud-service checks.
    ("BANK-001", "Unauthorized cross-customer account access", "critical",
     r"(?:access|retrieve|view|read|open|check|download|look\s+up|obtain)\b.{0,120}\b(?:another|other|different|someone else(?:'s|s))\b.{0,100}\b(?:customer|person|user|client)\b.{0,100}\b(?:account|balance|transaction|personal|details|history|profile)\b|\b(?:another|other|different)\s+customer(?:'s|s)?\s+(?:bank\s+)?account\b.{0,120}\b(?:without|unauthorized|no)\s+(?:authorization|permission|consent)\b|\bwithout\s+(?:authorization|permission|consent)\b.{0,120}\b(?:another|other|customer|account)\b|\b(?:unauthorized|unauthorised)\b.{0,100}\b(?:account|customer|banking|access|records?)\b|\b(?:account|customer|banking|records?)\b.{0,100}\bwithout\s+(?:authorization|permission|consent)\b",
     "DENY", "Potential unauthorized cross-customer account access."),
    ("BANK-002", "Banking credential or secret extraction", "critical",
     r"\b(?:attempt\s+to\s+)?(?:retrieve|reveal|dump|exfiltrate|show|extract|steal|list|obtain|expose|return|collect)\b.{0,140}\b(?:customer\s+)?(?:passwords?|pins?|one[- ]time passwords?|otps?|secret credentials|banking credentials|private keys|authentication secrets)\b|\b(?:passwords?|pins?|otps?|credentials?|authentication secrets)\b.{0,100}\b(?:all customers|customer database|database|other customers|bank database)\b|\b(?:customer\s+)?(?:passwords?|pins?|otps?)\b.{0,80}\b(?:retrieve|reveal|dump|expose|steal|extract)\b",
     "BLOCK", "Request attempts to expose banking credentials or authentication secrets."),
    ("BANK-004", "Sensitive banking action without clear authorization", "high",
     r"\b(?:access|open|retrieve|view|export|change|reset|transfer|withdraw)\b.{0,100}\b(?:bank\s+)?(?:account|customer\s+records?|transaction\s+history|beneficiary)\b.{0,100}\b(?:without|no|missing|unverified)\s+(?:authorization|permission|consent|verification)\b",
     "DENY", "Sensitive banking action explicitly lacks authorization or verification."),
    ("BANK-003", "High-value transfer needs review", "high",
     r"\b(?:transfer|wire|send|move)\b.{0,100}(?:₹\s*[\d,]+|rs\.?\s*[\d,]+|inr\s*[\d,]+|\b(?:large|high[- ]value|substantial)\s+(?:sum|amount|funds)\b)",
     "REVIEW", "Potential high-value transfer requires policy and customer confirmation review."),
    ("SEC-002","Secret or system prompt extraction","high",
     r"reveal\s+(the\s+)?(system prompt|api keys?|passwords?)|dump\s+(all\s+)?secrets",
     "BLOCK","Request attempts to expose hidden instructions or secrets."),
    ("PATH-001","Path traversal","critical",
     r"(\.\./|\\.\\.\\\\|/etc/passwd|/\.env|\\\.env|windows[\\/]+system32)",
     "BLOCK","Path traversal or protected path pattern detected."),
    ("CMD-001","Dangerous command pattern","critical",
     r"\brm\s+-rf\b|\bsudo\b|curl\s+.+\|\s*(sh|bash)\b|subprocess|os\.system\s*\(",
     "BLOCK","Potentially dangerous command execution pattern detected."),
    ("PRIV-001","Privilege escalation","high",
     r"\b(make me admin|grant superuser|disable access control|bypass approval)\b",
     "BLOCK","Attempt to bypass authorization or approval controls."),
    ("PII-001","Sensitive identifier in request","medium",
     r"\b\d{3}-\d{2}-\d{4}\b|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
     "REVIEW","Possible personal identifier detected; redact in evidence."),
]

def detect_patterns(text: str, policies: dict[str, Any] | None = None):
    policies = policies or {}
    findings=[]
    disable_map={"INJ-001":"block_prompt_injection","PATH-001":"block_path_traversal","CMD-001":"block_dangerous_commands"}
    for rid,name,severity,pattern,action,description in RULES:
        policy_key=disable_map.get(rid)
        if policy_key and not policies.get(policy_key, True):
            continue
        match=re.search(pattern,text,re.I)
        if match:
            evidence=match.group(0)
            if "@" in evidence or re.fullmatch(r"\d{3}-\d{2}-\d{4}", evidence):
                evidence="[REDACTED]"
            findings.append({"rule_id":rid,"name":name,"severity":severity,"description":description,
                "evidence":evidence[:80],"recommended_action":action,"score_contribution":{"critical":45,"high":30,"medium":15,"low":5}[severity]})
    return findings
