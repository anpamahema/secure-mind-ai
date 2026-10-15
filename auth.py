import hashlib, hmac, secrets, time
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Depends, HTTPException, Header
from config import SECRET_KEY, ACCESS_TOKEN_MINUTES
from database import connect

def hash_password(password: str) -> str:
    # PBKDF2-HMAC with per-user random salt; standard-library implementation avoids platform-specific setup.
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return "pbkdf2_sha256$310000$" + salt.hex() + "$" + digest.hex()

def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt_hex, digest_hex = encoded.split("$")
        if scheme != "pbkdf2_sha256": return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)).hex()
        return hmac.compare_digest(actual, digest_hex)
    except Exception:
        return False

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="securemind-access")

def issue_token(user: dict) -> str:
    return serializer.dumps({"uid": user["id"], "username": user["username"], "role": user["role"]})

def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in required")
    token = authorization[7:]
    try:
        data = serializer.loads(token, max_age=ACCESS_TOKEN_MINUTES*60)
    except SignatureExpired:
        raise HTTPException(401, "Session expired; sign in again")
    except BadSignature:
        raise HTTPException(401, "Invalid session")
    with connect() as c:
        row = c.execute("SELECT id,username,role,active FROM users WHERE id=?", (data.get("uid"),)).fetchone()
    if not row or not row["active"] or row["username"] != data.get("username") or row["role"] != data.get("role"):
        raise HTTPException(401, "Account unavailable; sign in again")
    return dict(row)

def require_roles(*roles):
    def checker(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, "Your role is not allowed to perform this action")
        return user
    return checker
