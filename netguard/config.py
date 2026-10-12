import os
import secrets
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "NetGuard Security Platform"
    SECRET_KEY: str = os.getenv("NETGUARD_SECRET_KEY") or secrets.token_urlsafe(48)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    DB_PATH: str = os.getenv("NETGUARD_DB", "netguard.db")
    ALLOWED_TARGETS: str = os.getenv("NETGUARD_ALLOWED_TARGETS", "127.0.0.0/8,192.168.56.0/24")
    MAX_CONCURRENT_SCANS: int = 2
    PBKDF2_ITERATIONS: int = 600000
    LOGIN_MAX_FAILURES: int = 5
    LOGIN_WINDOW_SECONDS: int = 300

settings = Settings()
