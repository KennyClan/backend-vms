import os
import uuid
from datetime import datetime, timedelta, timezone
import asyncpg
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from database import get_conn
from models import UserRole
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "")
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
    )
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 480))

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2  = OAuth2PasswordBearer(tokenUrl="/auth/login")


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)


def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)


def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


PRE_AUTH_EXPIRE_MINUTES = 5


def create_pre_auth_token(user_id: str) -> str:
    """Short-lived token proving 'password step passed' — not a session
    token. Carries scope=mfa_pending so it can't be used on any protected
    route; it only unlocks the webauthn /login/verify step."""
    payload = {
        "sub": user_id,
        "scope": "mfa_pending",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=PRE_AUTH_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_pre_auth_token(token: str) -> str:
    """Returns the user_id if the token is a valid, unexpired pre-auth
    token. Raises 401 otherwise."""
    cred_exc = HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Password verification expired — please log in again")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("scope") != "mfa_pending":
            raise cred_exc
        user_id = payload.get("sub")
        if not user_id:
            raise cred_exc
        return user_id
    except JWTError:
        raise cred_exc


async def get_current_user(
    token: str = Depends(oauth2),
    conn:  asyncpg.Connection = Depends(get_conn),
) -> dict:
    cred_exc = HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise cred_exc
    except JWTError:
        raise cred_exc
    row = await conn.fetchrow(
        "SELECT id, name, initials, email, role, is_active FROM staff_users WHERE id=$1",
        uuid.UUID(user_id),
    )
    if not row or not row["is_active"]:
        raise cred_exc
    return dict(row)


def require_roles(*roles: UserRole):
    async def checker(user: dict = Depends(get_current_user)):
        if user["role"] not in [r.value for r in roles]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user
    return checker
