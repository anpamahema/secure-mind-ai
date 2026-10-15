from database import audit
def record_event(actor, event, decision=None, request_id=None, details=None):
    audit(actor.get("id"), actor.get("username","system"), event, decision, request_id, details)
