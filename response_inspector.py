import re
def sanitize_response(value):
    """Mask common PII in displayable response text; authorization must happen before retrieval."""
    text = str(value)
    text = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[MASKED_EMAIL]", text, flags=re.I)
    text = re.sub(r"\b(?:\+?\d[\d .()-]{7,}\d)\b", "[MASKED_PHONE]", text)
    text = re.sub(r"\b(?:account|acct)[-_ ]?\d{5,}\b", "[MASKED_ACCOUNT]", text, flags=re.I)
    return text
