from fastapi import APIRouter, HTTPException, status
from netguard.api.schemas import UserCreate, UserLogin, TokenResponse
from netguard.auth.security import hash_password, verify_password, create_access_token
from netguard.database import get_connection

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: UserCreate):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (user.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Username already registered.")
        
        hashed_pwd = hash_password(user.password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (user.username, hashed_pwd, user.role)
        )
        conn.commit()
    return {"message": "User registered successfully"}

@router.post("/login", response_model=TokenResponse)
def login(credentials: UserLogin):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, role FROM users WHERE username = ?", (credentials.username,))
        row = cursor.fetchone()
        
        if not row or not verify_password(credentials.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        token = create_access_token(data={"sub": credentials.username, "role": row["role"]})
        return {"access_token": token, "token_type": "bearer"}