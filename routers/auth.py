import uuid
import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from database import get_conn
from schemas import TokenOut, MfaPendingOut
from utils.auth import verify_password, create_access_token, create_pre_auth_token, get_current_user
from utils.audit import write_audit
from limiter import limiter

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/login", response_model=MfaPendingOut)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    conn: asyncpg.Connection        = Depends(get_conn),
):
    row = await conn.fetchrow(
        "SELECT id, name, initials, email, password_hash, role, is_active FROM staff_users WHERE email=$1",
        form.username.lower(),
    )
    if not row or not verify_password(form.password, row["password_hash"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    if not row["is_active"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Account disabled")

    # BUG #2 FIX: The original query returned True for any row in
    # webauthn_credentials, even rows with null/empty credential_id or
    # public_key (e.g. a failed half-registration). That made the backend
    # tell the frontend "biometric already enrolled" (registration_required=False),
    # which caused the frontend to call /auth/webauthn/login/options — where
    # the stricter filter found *no* usable credential and returned 428.
    # The user was then completely locked out with no way to re-enroll.
    # Fix: use the same strict filter that webauthn.py already uses.
    has_credential = await conn.fetchval(
        """SELECT EXISTS(
             SELECT 1 FROM webauthn_credentials
             WHERE user_id=$1
               AND credential_id IS NOT NULL AND credential_id <> ''
               AND public_key    IS NOT NULL AND public_key    <> ''
           )""",
        row["id"],
    )

    pre_auth_token = create_pre_auth_token(str(row["id"]))
    await write_audit(conn, "Staff Login", actor={"id": row["id"], "name": row["name"]}, detail=f"Password step verified: {form.username}")
    return {"pre_auth_token": pre_auth_token, "registration_required": not has_credential}


@router.get("/me")
async def me(current: dict = Depends(get_current_user)):
    """Used by the frontend on page load to verify the stored JWT is still
    valid. Returns the current user object, or 401 if the token is expired,
    tampered with, or the account has been disabled."""
    return current


@router.post("/logout")
async def logout(
    current: dict              = Depends(get_current_user),
    conn:    asyncpg.Connection = Depends(get_conn),
):
    await write_audit(conn, "Staff Logout", actor=current)
    return {"detail": "Logged out"}
