import threading
from contextlib import contextmanager
from fastapi import HTTPException
from netguard.config import settings

_slots = threading.BoundedSemaphore(settings.MAX_CONCURRENT_SCANS)

@contextmanager
def scan_slot():
    if not _slots.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Scanner busy. Try again shortly.")
    try:
        yield
    finally:
        _slots.release()
