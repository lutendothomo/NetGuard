import os, hashlib, hmac, time
import jwt
from typing import Optional
from netguard.config import settings

LEGACY_ITERATIONS = 100000

def _derive(plain_password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt, iterations)

def hash_password(plain_password: str) -> str:
    salt = os.urandom(16)
    iterations = settings.PBKDF2_ITERATIONS
    return f"{iterations}${salt.hex()}${_derive(plain_password, salt, iterations).hex()}"

def verify_password(plain_password: str, stored_password: str) -> bool:
    try:
        parts = stored_password.split('$')
        if len(parts) == 2:
            iterations, salt_hex, hash_hex = LEGACY_ITERATIONS, parts[0], parts[1]
        else:
            iterations, salt_hex, hash_hex = int(parts[0]), parts[1], parts[2]
        expected_hash = bytes.fromhex(hash_hex)
        calculated_hash = _derive(plain_password, bytes.fromhex(salt_hex), iterations)
        return hmac.compare_digest(expected_hash, calculated_hash)
    except Exception:
        return False

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": time.time() + (settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_access_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.PyJWTError:
        return None
