import ipaddress
from pydantic import BaseModel, Field, field_validator

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8)
    role: str = Field(default="analyst", pattern=r"^(admin|analyst|auditor)$")

class UserLogin(BaseModel):
    username: str
    password: str

# ---> This was the missing class! <---
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AuditRequest(BaseModel):
    target_ip: str

    @field_validator("target_ip")
    def validate_ip_address(cls, value: str) -> str:
        ip = ipaddress.IPv4Address(value)
        if ip.is_link_local:
            raise ValueError("Target cannot be a metadata service address.")
        return str(ip)