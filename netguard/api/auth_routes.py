from fastapi import APIRouter, Depends, HTTPException, Request, status
from netguard.api.schemas import UserCreate, UserLogin, TokenResponse
from netguard.auth.rbac import require_role
from netguard.auth.security import hash_password, verify_password, create_access_token
from netguard.auth.throttle import check_login_allowed, record_failure, clear_failures
from netguard.database import get_connection

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

def _insert_user(username: str, password: str, role: str = None) -> str:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Username already registered.")
        if role is None:
            count = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            role = "admin" if count == 0 else "analyst"
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), role)
        )
        conn.commit()
    return role

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate):
    role = _insert_user(user.username, user.password)
    return {"message": "User registered successfully", "role": role}

@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, current_user: dict = Depends(require_role(["admin"]))):
    role = _insert_user(user.username, user.password, user.role)
    return {"message": "User created successfully", "role": role}

@router.post("/login", response_model=TokenResponse)
def login(credentials: UserLogin, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    key = f"{client_ip}:{credentials.username}"
    check_login_allowed(key)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, role FROM users WHERE username = ?", (credentials.username,))
        row = cursor.fetchone()

        if not row or not verify_password(credentials.password, row["password_hash"]):
            record_failure(key)
            raise HTTPException(status_code=401, detail="Invalid username or password")

        clear_failures(key)
        token = create_access_token(data={"sub": credentials.username, "role": row["role"]})
        return {"access_token": token, "token_type": "bearer"}
