import json
from typing import Iterable
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from netguard.auth.security import decode_access_token

security_scheme = HTTPBearer(auto_error=False)


def _extract_raw_token(raw_value: str) -> str:
    """Automatically extracts the JWT whether the user pastes raw text or the full JSON response."""
    text = raw_value.strip()
    # If the user pasted the JSON object from /api/auth/login, parse it out!
    if text.startswith("{") or "access_token" in text:
        try:
            data = json.loads(text)
            if isinstance(data, dict) and "access_token" in data:
                return str(data["access_token"]).strip()
        except Exception:
            # Fallback if they pasted partial JSON like: "access_token": "eyJ..."
            for part in text.replace('"', " ").replace("'", " ").replace(",", " ").split():
                if part.startswith("eyJ"):
                    return part.strip()

    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    return text.strip('"').strip("'")


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
) -> dict:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = _extract_raw_token(credentials.credentials)
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


def require_role(allowed_roles: Iterable[str] | str):
    if isinstance(allowed_roles, str):
        allowed_set = {allowed_roles}
    else:
        allowed_set = set(allowed_roles)

    def role_checker(user: dict = Depends(get_current_user)) -> dict:
        if user.get("role") not in allowed_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return user

    return role_checker