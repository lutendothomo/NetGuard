import ipaddress
from typing import Optional
from pydantic import BaseModel, Field, field_validator
from netguard.core.scope import ip_in_scope, network_in_scope

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8)
    role: str = Field(default="analyst", pattern=r"^(admin|analyst|auditor)$")

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AuditRequest(BaseModel):
    target_ip: str

    @field_validator("target_ip")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        ip = ipaddress.IPv4Address(value)
        if ip.is_link_local:
            raise ValueError("Target cannot be a metadata service address.")
        if not ip_in_scope(str(ip)):
            raise ValueError("Target is outside the authorized scope.")
        return str(ip)

class ScanRequest(AuditRequest):
    ports: Optional[list[int]] = None

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: Optional[list[int]]) -> Optional[list[int]]:
        if value is None:
            return value
        if not value or len(value) > 1024 or any(port < 1 or port > 65535 for port in value):
            raise ValueError("Provide 1-1024 ports between 1 and 65535.")
        return sorted(set(value))

class DiscoverRequest(BaseModel):
    subnet: str

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, value: str) -> str:
        network = ipaddress.IPv4Network(value, strict=False)
        if network.prefixlen < 24:
            raise ValueError("Subnet must be /24 or smaller.")
        if not network_in_scope(str(network)):
            raise ValueError("Subnet is outside the authorized scope.")
        return str(network)
