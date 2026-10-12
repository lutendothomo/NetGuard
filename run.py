from contextlib import asynccontextmanager
import uvicorn
from fastapi import FastAPI, Request

from netguard.database import init_db
from netguard.api.auth_routes import router as auth_router
from netguard.api.audit_routes import router as audit_router
from netguard.api.network_routes import router as network_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="NetGuard Security Platform", lifespan=lifespan)


@app.middleware("http")
async def apply_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"

    # Allow Swagger UI / ReDoc CDN assets on documentation paths; enforce strict CSP everywhere else
    if request.url.path in ("/docs", "/redoc", "/openapi.json"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com;"
        )
    else:
        response.headers["Content-Security-Policy"] = "default-src 'self';"

    return response


app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(network_router)


if __name__ == "__main__":
    uvicorn.run("run:app", host="127.0.0.1", port=8000, reload=True)