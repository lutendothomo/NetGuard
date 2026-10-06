import os, hashlib, hmac, time
import jwt
from typing import Optional
from netguard.config import settings

def hash_password(plain_password: str) -> str:
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt, 100000)
    return f"{salt.hex()}${pwd_hash.hex()}"

def verify_password(plain_password: str, stored_password: str) -> bool:
    try:
        salt_hex, hash_hex = stored_password.split('$')
        salt, expected_hash = bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
        calculated_hash = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt, 100000)
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