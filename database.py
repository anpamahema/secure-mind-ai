import sqlite3, json
from pathlib import Path
from config import DATABASE_PATH

def connect():
    p = Path(DATABASE_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p), timeout=10, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    return con

def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, full_name TEXT NOT NULL DEFAULT '', username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('Admin','Security Reviewer','Analyst','Standard User')),
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS tools(
          id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, server_name TEXT NOT NULL DEFAULT 'demo',
          description TEXT NOT NULL DEFAULT '', sensitivity TEXT NOT NULL DEFAULT 'low',
          enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS policies(
          key TEXT PRIMARY KEY, value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS requests(
          id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), username TEXT NOT NULL,
          profile TEXT NOT NULL, server_name TEXT, tool_name TEXT, request_text TEXT NOT NULL,
          risk_score INTEGER NOT NULL, severity TEXT NOT NULL, decision TEXT NOT NULL,
          findings TEXT NOT NULL, explanation TEXT NOT NULL, execution_status TEXT NOT NULL DEFAULT 'NOT_EXECUTED',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS approvals(
          id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL REFERENCES requests(id),
          requester_id INTEGER NOT NULL REFERENCES users(id), requester_name TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','APPROVED','REJECTED','FALSE_POSITIVE')),
          reason TEXT NOT NULL, explanation TEXT NOT NULL DEFAULT '',
          reviewer_id INTEGER REFERENCES users(id), reviewer_name TEXT,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, decided_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY, request_id INTEGER, actor_id INTEGER, actor_name TEXT NOT NULL,
          event TEXT NOT NULL, decision TEXT, details TEXT NOT NULL DEFAULT '{}',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS transactions(
          id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL REFERENCES requests(id),
          requester_id INTEGER NOT NULL REFERENCES users(id), account_id TEXT NOT NULL,
          amount REAL NOT NULL CHECK(amount >= 0), status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','REJECTED','EXECUTED')),
          idempotency_key TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, executed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS accounts(
          account_id TEXT PRIMARY KEY, owner_user_id INTEGER NOT NULL REFERENCES users(id),
          balance REAL NOT NULL DEFAULT 100000 CHECK(balance >= 0)
        );
        CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit(created_at);
        CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
        """)
        # Migrate databases created by earlier project versions.
        user_columns = {row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()}
        if "full_name" not in user_columns:
            c.execute("ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT ''")
        defaults = {
          "block_prompt_injection": True, "block_path_traversal": True,
          "block_dangerous_commands": True, "require_transaction_approval": True,
          "transaction_threshold": 10000
        }
        for k,v in defaults.items():
            c.execute("INSERT OR IGNORE INTO policies(key,value) VALUES(?,?)",(k,json.dumps(v)))
        seed = [
          ("demo.search_public_docs","demo","Search synthetic public documentation","low",1),
          ("demo.get_customer_record","demo","Read a synthetic customer record","medium",1),
          ("demo.export_dataset","demo","Export synthetic dataset","high",1),
          ("demo.create_issue","demo","Create a synthetic developer issue","medium",1),
          ("demo.transfer_funds","demo","Synthetic banking transaction; never real money","high",1),
        ]
        for row in seed:
            c.execute("INSERT OR IGNORE INTO tools(name,server_name,description,sensitivity,enabled) VALUES(?,?,?,?,?)",row)

def policies():
    with connect() as c:
        rows = c.execute("SELECT key,value FROM policies").fetchall()
    return {r["key"]: json.loads(r["value"]) for r in rows}

def audit(actor_id, actor_name, event, decision=None, request_id=None, details=None):
    with connect() as c:
        c.execute("INSERT INTO audit(request_id,actor_id,actor_name,event,decision,details) VALUES(?,?,?,?,?,?)",
                  (request_id, actor_id, actor_name, event, decision, json.dumps(details or {})))
