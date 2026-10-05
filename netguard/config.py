import os
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "NetGuard Security Platform"
    # In production, set this via ENV: export NETGUARD_SECRET_KEY="..."
    SECRET_KEY: str = os.getenv("NETGUARD_SECRET_KEY", "dev-key-change-me-immediately")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    DB_PATH: str = os.getenv("NETGUARD_DB", "netguard.db")

settings = Settings()