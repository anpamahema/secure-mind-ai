from database import connect, audit
from fastapi import HTTPException

def decide_approval(approval_id, reviewer, action, explanation):
    if reviewer["role"] not in ("Admin","Security Reviewer"):
        raise HTTPException(403, "Reviewer role required")
    if action == "APPROVE":
        action_status = "APPROVED"
    elif action == "REJECT":
        action_status = "REJECTED"
    elif action == "FALSE_POSITIVE":
        action_status = "FALSE_POSITIVE"
    else:
        raise HTTPException(400, "Unknown decision")
    with connect() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if not row or row["status"] != "PENDING":
            c.rollback()
            raise HTTPException(409, "Approval is no longer pending")
        req = c.execute("SELECT * FROM requests WHERE id=?", (row["request_id"],)).fetchone()
        # Never let approval bypass mandatory BLOCK or DENY decisions.
        if action == "APPROVE" and req["decision"] in ("BLOCK","DENY"):
            c.rollback()
            raise HTTPException(409, "Mandatory security decisions cannot be overridden")
        c.execute("UPDATE approvals SET status=?,explanation=?,reviewer_id=?,reviewer_name=?,decided_at=CURRENT_TIMESTAMP WHERE id=? AND status='PENDING'",
                  (action_status, explanation, reviewer["id"], reviewer["username"], approval_id))
        if action == "APPROVE":
            # This demo marks the approval decision only. It does not automatically run arbitrary tools.
            c.execute("UPDATE requests SET execution_status='APPROVED_NOT_EXECUTED' WHERE id=?", (row["request_id"],))
        elif action == "REJECT":
            c.execute("UPDATE requests SET execution_status='REJECTED_NOT_EXECUTED' WHERE id=?", (row["request_id"],))
        c.execute("INSERT INTO audit(request_id,actor_id,actor_name,event,decision,details) VALUES(?,?,?,?,?,?)",
                  (row["request_id"], reviewer["id"], reviewer["username"], "approval_decision", action_status,
                   __import__("json").dumps({"explanation": explanation})))
        c.commit()
    return {"ok": True, "status": action_status}
