import uvicorn
from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
from netguard.database import init_db
from netguard.api.auth_routes import router as auth_router
from netguard.api.audit_routes import router as audit_router
from netguard.api.network_routes import router as network_router

# Modern FastAPI Lifespan (Replaces the deprecated @app.on_event)
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db() # Run startup tasks
    yield     # Server runs while yielding

app = FastAPI(title="NetGuard Security Platform", lifespan=lifespan)

@app.middleware("http")
async def apply_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self';"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response

app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(network_router)

if __name__ == "__main__":
    # FIX: Use "run:app" instead of "run.py:app"
    uvicorn.run("run:app", host="127.0.0.1", port=8000, reload=True)