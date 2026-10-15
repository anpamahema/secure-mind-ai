import os, sys, json, secrets, argparse, yaml
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from pydantic import ValidationError
from config import CORS_ORIGINS, RULES_PATH
from database import init_db, connect, policies
from auth import hash_password, verify_password, issue_token, current_user, require_roles
from models import LoginRequest, SignupRequest, UserCreate, InspectRequest, ApprovalDecision, PolicyUpdate
from mcp_gateway import evaluate_and_record
from approval_service import decide_approval
from audit_service import record_event
from response_inspector import sanitize_response

init_db()
# On Render, bootstrap the first administrator only when the database is empty.
# The password comes from Render's secret environment variable; no default credential is used.
_bootstrap_password = os.getenv("SECMIND_ADMIN_PASSWORD", "")
if _bootstrap_password and len(_bootstrap_password) >= 12:
    with connect() as _c:
        _has_users = _c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if not _has_users:
            _username = os.getenv("SECMIND_ADMIN_USERNAME", "admin").strip() or "admin"
            _cur = _c.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,'Admin')",
                              (_username, hash_password(_bootstrap_password)))
            _c.execute("INSERT OR IGNORE INTO accounts(account_id,owner_user_id,balance) VALUES(?,?,100000)",
                       (f"demo:{_cur.lastrowid}", _cur.lastrowid))
if not RULES_PATH.exists():
    raise RuntimeError(f"Security rule file missing: {RULES_PATH}")
try:
    with open(RULES_PATH, encoding="utf-8") as f:
        RULE_CONFIG = yaml.safe_load(f)
    if not isinstance(RULE_CONFIG, dict) or not isinstance(RULE_CONFIG.get("rules"), list):
        raise ValueError("Expected top-level rules list")
except Exception as e:
    raise RuntimeError(f"Invalid security rules configuration: {e}") from e

app = FastAPI(title="SecureMind AI", description="Inspect. Enforce. Audit.", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=False,
                   allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"], allow_headers=["Authorization","Content-Type"])

# Simple in-process login throttling for local demo; use a shared rate limiter in production.
LOGIN_ATTEMPTS = {}
@app.middleware("http")
async def login_throttle(request: Request, call_next):
    if request.url.path == "/api/auth/login" and request.method == "POST":
        ip = request.client.host if request.client else "unknown"
        now = datetime.now().timestamp()
        bucket = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now-t < 60]
        if len(bucket) >= 10:
            return JSONResponse(status_code=429, content={"detail":"Too many login attempts; wait a minute"})
        bucket.append(now); LOGIN_ATTEMPTS[ip] = bucket
    return await call_next(request)

@app.get("/")
def root():
    return {"service":"SecureMind AI","tagline":"Inspect. Enforce. Audit.","frontend":"http://localhost:5173/","docs":"/docs"}

@app.get("/health")
def health():
    return {"status":"ok","service":"SecureMind AI","policy_build":"securemind-policy-v4-multidomain","time":datetime.now(timezone.utc).isoformat()}

@app.post("/api/auth/signup")
def signup(body: SignupRequest):
    full_name = " ".join(body.full_name.split()).strip()
    if len(full_name) < 2:
        raise HTTPException(422, "Please enter your full name")
    with connect() as c:
        try:
            cur = c.execute("INSERT INTO users(full_name,username,password_hash,role) VALUES(?,?,?,'Standard User')",
                            (full_name, body.username, hash_password(body.password)))
            uid = cur.lastrowid
            c.execute("INSERT OR IGNORE INTO accounts(account_id,owner_user_id,balance) VALUES(?,?,100000)",
                      (f"demo:{uid}", uid))
        except Exception as e:
            if "UNIQUE" in str(e): raise HTTPException(409, "That username is already taken; choose another")
            raise
        row = c.execute("SELECT id,full_name,username,role FROM users WHERE id=?", (uid,)).fetchone()
    user = dict(row)
    token = issue_token(user)
    record_event(user, "signup", details={"username": body.username})
    return {"access_token":token,"token_type":"bearer","user":user}

@app.post("/api/auth/login")
def login(body: LoginRequest):
    with connect() as c:
        row = c.execute("SELECT * FROM users WHERE username=? AND active=1", (body.username,)).fetchone()
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    user = {"id":row["id"],"full_name":row["full_name"],"username":row["username"],"role":row["role"]}
    token = issue_token(user)
    record_event(user, "login")
    return {"access_token":token,"token_type":"bearer","user":user}

@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return {"id":user["id"],"full_name":user.get("full_name", ""),"username":user["username"],"role":user["role"]}

@app.post("/api/auth/logout")
def logout(user=Depends(current_user)):
    # Signed bearer tokens expire; client removes its token. Production should add revocation.
    record_event(user, "logout")
    return {"ok":True}

@app.post("/api/users")
def create_user(body: UserCreate, admin=Depends(require_roles("Admin"))):
    with connect() as c:
        try:
            cur = c.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                            (body.username, hash_password(body.password), body.role))
            uid = cur.lastrowid
            # Each created account gets a synthetic account for the banking demonstration.
            c.execute("INSERT OR IGNORE INTO accounts(account_id,owner_user_id,balance) VALUES(?,?,?)",
                      (f"demo:{uid}", uid, 100000))
        except Exception as e:
            if "UNIQUE" in str(e): raise HTTPException(409,"Username already exists")
            raise
    record_event(admin, "user_created", details={"username":body.username,"role":body.role})
    return {"id":uid,"username":body.username,"role":body.role}

@app.get("/api/users")
def list_users(admin=Depends(require_roles("Admin"))):
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT id,username,role,active,created_at FROM users ORDER BY id").fetchall()]

@app.get("/api/tools")
def list_tools(user=Depends(current_user)):
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT id,name,server_name,description,sensitivity,enabled FROM tools ORDER BY id").fetchall()]

@app.post("/api/tools")
def add_tool(body: dict, admin=Depends(require_roles("Admin"))):
    name=str(body.get("name","")).strip()
    if not name or len(name)>160 or any(x in name for x in (" ","/","\\",";")):
        raise HTTPException(422,"Invalid tool name")
    with connect() as c:
        try:
            cur=c.execute("INSERT INTO tools(name,server_name,description,sensitivity,enabled) VALUES(?,?,?,?,?)",
              (name,str(body.get("server_name","demo"))[:160],str(body.get("description",""))[:500],
               body.get("sensitivity","low") if body.get("sensitivity") in ("low","medium","high") else "low",1 if body.get("enabled",True) else 0))
        except Exception as e:
            if "UNIQUE" in str(e): raise HTTPException(409,"Tool already exists")
            raise
    record_event(admin,"tool_registered",details={"tool":name})
    return {"id":cur.lastrowid,"name":name}

@app.post("/api/inspect")
def inspect(body: InspectRequest, user=Depends(current_user)):
    p=policies()
    tool, findings, score, severity, decision, explanation = evaluate_and_record(user, body, p)
    # Banking review is queued; tool execution intentionally does not occur on this endpoint.
    execution_status = "NOT_EXECUTED"
    with connect() as c:
        cur=c.execute("""INSERT INTO requests(user_id,username,profile,server_name,tool_name,request_text,risk_score,severity,decision,findings,explanation,execution_status)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          (user["id"],user["username"],body.profile,body.server_name,body.tool_name,body.text,score,severity,decision,json.dumps(findings),explanation,execution_status))
        req_id=cur.lastrowid
        if decision=="REVIEW":
            c.execute("INSERT INTO approvals(request_id,requester_id,requester_name,status,reason) VALUES(?,?,?,'PENDING',?)",
                      (req_id,user["id"],user["username"],explanation))
        c.execute("INSERT INTO audit(request_id,actor_id,actor_name,event,decision,details) VALUES(?,?,?,?,?,?)",
                  (req_id,user["id"],user["username"],"request_inspected",decision,json.dumps({"risk_score":score,"severity":severity,"tool":body.tool_name})))
    return {"request_id":req_id,"audit_event_id":req_id,"risk_score":score,"severity":severity,"findings":findings,
            "decision":decision,"explanation":explanation,"execution_status":execution_status,
            "approval_status":"PENDING" if decision=="REVIEW" else None,
            "sanitized_preview":sanitize_response("Synthetic result preview only. No protected tool was executed.")}

@app.get("/api/approvals")
def get_approvals(user=Depends(require_roles("Admin","Security Reviewer"))):
    with connect() as c:
        rows=c.execute("""SELECT a.*,r.profile,r.server_name,r.tool_name,r.request_text,r.risk_score,r.severity,r.decision,r.findings
          FROM approvals a JOIN requests r ON r.id=a.request_id ORDER BY a.id DESC""").fetchall()
    result=[]
    for r in rows:
        item=dict(r); item["findings"]=json.loads(item["findings"]); result.append(item)
    return result

@app.post("/api/approvals/{approval_id}/decision")
def approval_decision(approval_id:int, body:ApprovalDecision, user=Depends(require_roles("Admin","Security Reviewer"))):
    with connect() as c:
        row=c.execute("SELECT requester_id FROM approvals WHERE id=?",(approval_id,)).fetchone()
    if not row: raise HTTPException(404,"Approval not found")
    if row["requester_id"]==user["id"] and user["role"]!="Admin":
        raise HTTPException(403,"Separation of duties: you cannot review your own request")
    return decide_approval(approval_id,user,body.action,body.explanation)

@app.get("/api/audit")
def get_audit(limit:int=100, offset:int=0, decision:str|None=None, user=Depends(current_user)):
    if user["role"] not in ("Admin","Security Reviewer","Analyst"):
        raise HTTPException(403,"Audit access requires Analyst, Reviewer, or Admin role")
    limit=max(1,min(limit,250)); offset=max(0,offset)
    with connect() as c:
        if decision:
            rows=c.execute("SELECT * FROM requests WHERE decision=? ORDER BY id DESC LIMIT ? OFFSET ?",(decision.upper(),limit,offset)).fetchall()
        else:
            rows=c.execute("SELECT * FROM requests ORDER BY id DESC LIMIT ? OFFSET ?",(limit,offset)).fetchall()
    result=[]
    for r in rows:
        d=dict(r); d["findings"]=json.loads(d["findings"]); result.append(d)
    return result

@app.get("/api/dashboard/stats")
def dashboard_stats(user=Depends(current_user)):
    with connect() as c:
        total=c.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
        counts={x:c.execute("SELECT COUNT(*) FROM requests WHERE decision=?",(x,)).fetchone()[0] for x in ("ALLOW","BLOCK","DENY","REVIEW")}
        pending=c.execute("SELECT COUNT(*) FROM approvals WHERE status='PENDING'").fetchone()[0]
        high=c.execute("SELECT COUNT(*) FROM requests WHERE risk_score>=60").fetchone()[0]
        tools=c.execute("SELECT COUNT(*) FROM tools WHERE enabled=1").fetchone()[0]
        return {"total_requests":total,"decisions":counts,"pending_approvals":pending,"high_risk":high,"enabled_tools":tools}

@app.get("/api/dashboard/history")
def dashboard_history(user=Depends(current_user)):
    with connect() as c:
        rows=c.execute("SELECT id,risk_score,decision,created_at FROM requests ORDER BY id DESC LIMIT 30").fetchall()
    return [dict(r) for r in rows][::-1]

@app.get("/api/policies")
def get_policies(user=Depends(current_user)):
    return policies()

@app.put("/api/policies")
def put_policies(body:PolicyUpdate,user=Depends(require_roles("Admin"))):
    values=body.model_dump(exclude_none=True)
    with connect() as c:
        for k,v in values.items():
            c.execute("INSERT INTO policies(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(k,json.dumps(v)))
    record_event(user,"policies_updated",details=values)
    return policies()

@app.post("/api/banking/transactions")
def banking_transaction(body:dict,user=Depends(current_user)):
    """Synthetic transaction flow. No real money or external banking system."""
    account_id=str(body.get("account_id",""))
    amount=body.get("amount")
    key=str(body.get("idempotency_key") or secrets.token_urlsafe(18))
    try: amount=float(amount)
    except Exception: raise HTTPException(422,"amount must be numeric")
    if amount<=0: raise HTTPException(422,"amount must be greater than zero")
    with connect() as c:
        account=c.execute("SELECT * FROM accounts WHERE account_id=? AND owner_user_id=?",(account_id,user["id"])).fetchone()
        if not account: raise HTTPException(403,"Synthetic account not found or not owned by this user")
        existing=c.execute("SELECT * FROM transactions WHERE idempotency_key=?",(key,)).fetchone()
        if existing: return dict(existing)
    req=InspectRequest(text=f"Transfer {amount} from synthetic account",profile="Banking",
        tool_name="demo.transfer_funds",server_name="demo",transaction_amount=amount,
        arguments={"account_id":account_id,"amount":amount})
    p=policies()
    tool,findings,score,severity,decision,explanation=evaluate_and_record(user,req,p)
    # Transaction permission is stricter than normal tool inspection.
    if user["role"] not in ("Admin","Security Reviewer"):
        decision="DENY"; explanation="Role is not permitted to initiate synthetic transactions."
    with connect() as c:
        c.execute("BEGIN IMMEDIATE")
        cur=c.execute("""INSERT INTO requests(user_id,username,profile,server_name,tool_name,request_text,risk_score,severity,decision,findings,explanation,execution_status)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
          (user["id"],user["username"],"Banking","demo","demo.transfer_funds",req.text,score,severity,decision,json.dumps(findings),explanation,"NOT_EXECUTED"))
        rid=cur.lastrowid
        if decision=="DENY" or decision=="BLOCK":
            status="REJECTED"
        elif amount>=float(p.get("transaction_threshold",10000)) and p.get("require_transaction_approval",True):
            status="PENDING"; decision="REVIEW"
        else:
            status="PENDING" # Even below threshold, synthetic transfers require a reviewer in this demo.
            decision="REVIEW"
        c.execute("UPDATE requests SET decision=? WHERE id=?",(decision,rid))
        cur=c.execute("INSERT INTO transactions(request_id,requester_id,account_id,amount,status,idempotency_key) VALUES(?,?,?,?,?,?)",
          (rid,user["id"],account_id,amount,status,key))
        tid=cur.lastrowid
        if status=="PENDING":
            c.execute("INSERT INTO approvals(request_id,requester_id,requester_name,status,reason) VALUES(?,?,?,'PENDING',?)",
                      (rid,user["id"],user["username"],f"Synthetic transaction ₹{amount:,.2f} requires human approval."))
        c.execute("INSERT INTO audit(request_id,actor_id,actor_name,event,decision,details) VALUES(?,?,?,?,?,?)",
          (rid,user["id"],user["username"],"synthetic_transaction_created",decision,json.dumps({"transaction_id":tid,"amount":amount,"status":status})))
        c.commit()
    return {"transaction_id":tid,"request_id":rid,"status":status,"decision":decision,"amount":amount,
            "message":"Synthetic transaction recorded. No balance changed and no real money moved."}

@app.post("/api/users/bootstrap")
def bootstrap_admin(body:dict):
    # One-time bootstrap: only works if there are no users yet; prefer CLI in normal setup.
    with connect() as c:
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            raise HTTPException(409,"An administrator already exists")
        username=str(body.get("username","admin"))
        password=str(body.get("password",""))
        if len(password)<12: raise HTTPException(422,"Bootstrap password must be at least 12 characters")
        cur=c.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,'Admin')",(username,hash_password(password)))
        uid=cur.lastrowid
        c.execute("INSERT INTO accounts(account_id,owner_user_id,balance) VALUES(?,?,100000)",(f"demo:{uid}",uid))
    return {"ok":True,"username":username}

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--init-admin",action="store_true")
    args=parser.parse_args()
    if args.init_admin:
        with connect() as c:
            exists=c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if exists:
            print("Users already exist; administrator initialization skipped.")
        else:
            username=os.getenv("SECMIND_ADMIN_USERNAME","admin")
            password=os.getenv("SECMIND_ADMIN_PASSWORD") or secrets.token_urlsafe(16)
            with connect() as c:
                cur=c.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",(username,hash_password(password),"Admin"))
                c.execute("INSERT INTO accounts(account_id,owner_user_id,balance) VALUES(?,?,100000)",(f"demo:{cur.lastrowid}",cur.lastrowid))
            print(f"Created first administrator: {username}")
            if not os.getenv("SECMIND_ADMIN_PASSWORD"): print(f"One-time generated password: {password}")
        sys.exit(0)
    import uvicorn
    uvicorn.run("main:app",host="127.0.0.1",port=8000,reload=False)
