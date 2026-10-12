import time
import threading
from fastapi import HTTPException
from netguard.config import settings

_failures = {}
_lock = threading.Lock()

def _recent(key: str) -> list:
    cutoff = time.time() - settings.LOGIN_WINDOW_SECONDS
    return [t for t in _failures.get(key, []) if t > cutoff]

def check_login_allowed(key: str) -> None:
    with _lock:
        recent = _recent(key)
        _failures[key] = recent
        if len(recent) >= settings.LOGIN_MAX_FAILURES:
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

def record_failure(key: str) -> None:
    with _lock:
        _failures.setdefault(key, []).append(time.time())

def clear_failures(key: str) -> None:
    with _lock:
        _failures.pop(key, None)
