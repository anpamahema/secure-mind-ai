import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "securemind.db"))
SECRET_KEY = os.getenv("SECRET_KEY", "local-development-only-change-this-secret")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "60"))
CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()]
RULES_PATH = BASE_DIR / "requirements" / "security_rules.yaml"
