def calculate_risk(findings, profile="Enterprise", sensitivity="low", transaction_amount=None):
    score = min(100, sum(int(f.get("score_contribution", 0)) for f in findings))
    if sensitivity == "high": score += 10
    elif sensitivity == "medium": score += 5
    if transaction_amount is not None and transaction_amount >= 10000: score += 20
    if profile.lower() in {"banking","fintech"} and transaction_amount is not None: score += 5
    score = min(100, score)
    severity = "low" if score < 30 else "medium" if score < 60 else "high" if score < 80 else "critical"
    return score, severity
