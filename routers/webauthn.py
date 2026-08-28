"""
WebAuthn (Face ID / fingerprint) support for Vista VMS.

This adds a *second* way to prove who you are, on top of the existing
email+password login in routers/auth.py — it never replaces it. Nothing in
here ever sees or stores an actual fingerprint/face scan; the phone's
Secure Enclave/TEE keeps that, and only ever hands us a public key and
signed challenges.

Flow (all staff, every login — password AND biometric required):
  1. Staff submits email+password to POST /auth/login (routers/auth.py).
     On success this does NOT return a usable session token — it returns a
     short-lived pre_auth_token (5 min) that only proves "password step
     passed". See utils/auth.create_pre_auth_token / verify_pre_auth_token.
  2. Frontend calls /login/options below, sending that pre_auth_token, to
     get a random challenge from the server.
  3. Frontend passes that to the browser's WebAuthn API
     (navigator.credentials.get, e.g. via @simplewebauthn/browser), which
     triggers the native Face ID / fingerprint prompt.
  4. Frontend POSTs the signed result + the same pre_auth_token to
     /login/verify below.
  5. Only now is a real session JWT issued (create_access_token) — same
     shape /auth/login used to return, so everything downstream
     (require_roles, audit logging, dashboard) is unchanged.

First-time device setup uses the identical pre_auth_token from step 1 —
/register/options and /register/verify below — so a brand-new staff
account still has to pass the password check before it can enroll a
device. There is no way to reach the dashboard with only one factor.
"""

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from database import get_conn
from schemas import TokenOut
from utils.audit import write_audit
from utils.auth import create_access_token, verify_pre_auth_token, resolve_permissions
from limiter import limiter

router = APIRouter(prefix="/auth/webauthn", tags=["WebAuthn"])

# --- Relying Party config -----------------------------------------------
# RP_ID must be the bare domain your frontend is served from (no scheme, no
# port). EXPECTED_ORIGIN is the full origin.
#
# Resolution order:
#   1. WEBAUTHN_RP_ID / WEBAUTHN_ORIGIN env vars (explicit, always win).
#   2. Auto-derived from the first non-localhost origin in CORS_ORIGINS —
#      the frontend's production origin — so fingerprint/Face ID keeps
#      working without extra env vars, as long as CORS_ORIGINS is set.
#   3. localhost fallbacks for local development.
import os
from urllib.parse import urlparse

RP_ID = os.getenv("WEBAUTHN_RP_ID", "")
EXPECTED_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "")
if not RP_ID or not EXPECTED_ORIGIN:
    for _origin in [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]:
        _parsed = urlparse(_origin)
        if _parsed.scheme in ("http", "https") and _parsed.hostname and _parsed.hostname not in ("localhost", "127.0.0.1"):
            if not EXPECTED_ORIGIN:
                EXPECTED_ORIGIN = _origin
            if not RP_ID:
                RP_ID = _parsed.hostname
            break
if not RP_ID:
    RP_ID = "localhost"
if not EXPECTED_ORIGIN:
    EXPECTED_ORIGIN = "http://localhost:5173"
RP_NAME = "Vista VMS"
logger.info("WebAuthn RP_ID=%s EXPECTED_ORIGIN=%s", RP_ID, EXPECTED_ORIGIN)

if RP_ID == "localhost" and os.getenv("ENVIRONMENT", "development") == "production":
    logger.warning(
        "WEBAUTHN_RP_ID is still 'localhost' in production. "
        "Set CORS_ORIGINS to your frontend URL (e.g. https://frontend-vms-sand.vercel.app) "
        "on Render, or set WEBAUTHN_RP_ID / WEBAUTHN_ORIGIN explicitly — "
        "otherwise fingerprint registration will fail with 'cancelled/timed out'."
    )

CHALLENGE_TTL_MINUTES = 5


class PreAuthIn(BaseModel):
    pre_auth_token: str


class RegistrationVerifyIn(BaseModel):
    pre_auth_token: str
    credential: dict
    nickname: str | None = None


class AuthenticationVerifyIn(BaseModel):
    pre_auth_token: str
    credential: dict


async def _get_user_row(conn: asyncpg.Connection, user_id: uuid.UUID):
    row = await conn.fetchrow(
        "SELECT id, name, initials, email, role, is_active, permissions FROM staff_users WHERE id=$1",
        user_id,
    )
    if not row or not row["is_active"]:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return row


async def _store_challenge(conn: asyncpg.Connection, user_id: uuid.UUID, challenge: bytes, purpose: str):
    # One live challenge per (user, purpose) at a time — clear any stale one
    # first so an abandoned attempt can't be replayed later.
    await conn.execute(
        "DELETE FROM webauthn_challenges WHERE user_id=$1 AND purpose=$2",
        user_id, purpose,
    )
    await conn.execute(
        """
        INSERT INTO webauthn_challenges (user_id, challenge, purpose, expires_at)
        VALUES ($1, $2, $3, $4)
        """,
        user_id,
        challenge.hex(),
        purpose,
        datetime.now(timezone.utc) + timedelta(minutes=CHALLENGE_TTL_MINUTES),
    )


async def _pop_challenge(conn: asyncpg.Connection, user_id: uuid.UUID, purpose: str) -> bytes:
    row = await conn.fetchrow(
        """
        DELETE FROM webauthn_challenges
        WHERE user_id=$1 AND purpose=$2 AND expires_at > now()
        RETURNING challenge
        """,
        user_id, purpose,
    )
    if not row:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Challenge expired or not found — please try again")
    return bytes.fromhex(row["challenge"])


# -------------------------------------------------------------------------
# 1. Registration options — first-time device setup. Requires the
#    pre_auth_token from a just-completed POST /auth/login, so you must
#    already know the password to enroll a new device.
# -------------------------------------------------------------------------
@router.post("/register/options")
@limiter.limit("5/minute")
async def registration_options(
    request: Request,
    body: PreAuthIn,
    conn: asyncpg.Connection = Depends(get_conn),
):
    user_id = uuid.UUID(verify_pre_auth_token(body.pre_auth_token))
    user_row = await _get_user_row(conn, user_id)

    existing = await conn.fetch(
        "SELECT credential_id FROM webauthn_credentials WHERE user_id=$1 AND credential_id IS NOT NULL AND credential_id <> '' AND public_key IS NOT NULL AND public_key <> ''",
        user_id,
    )

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user_id).encode(),
        user_name=user_row["email"],
        user_display_name=user_row["name"],
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"]))
            for r in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,  # forces biometric/PIN, not just "device present"
        ),
    )

    await _store_challenge(conn, user_id, options.challenge, "registration")
    return {"options": options_to_json(options)}


# -------------------------------------------------------------------------
# 2. Registration verify — stores the public key returned by the device.
# -------------------------------------------------------------------------
@router.post("/register/verify")
@limiter.limit("5/minute")
async def registration_verify(
    request: Request,
    body: RegistrationVerifyIn,
    conn: asyncpg.Connection = Depends(get_conn),
):
    user_id = uuid.UUID(verify_pre_auth_token(body.pre_auth_token))
    user_row = await _get_user_row(conn, user_id)
    challenge = await _pop_challenge(conn, user_id, "registration")

    try:
        credential = parse_registration_credential_json(_dict_to_json(body.credential))
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=True,
        )
    except Exception as exc:
        logger.exception("WebAuthn registration verify failed: %s", exc)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Could not verify this device's response")

    await conn.execute(
        """
        INSERT INTO webauthn_credentials
            (user_id, credential_id, public_key, sign_count, device_type, nickname)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        user_id,
        _bytes_to_b64url(verification.credential_id),
        _bytes_to_b64url(verification.credential_public_key),
        verification.sign_count,
        "platform",
        body.nickname,
    )
    await write_audit(conn, "Biometric Registered", actor=dict(user_row), detail=f"Biometric device registered: {body.nickname}")
    return {"detail": "Biometric login enabled for this device"}


# -------------------------------------------------------------------------
# 3. Login options — second factor. Requires the pre_auth_token issued by
#    a successful POST /auth/login password check.
# -------------------------------------------------------------------------
@router.post("/login/options")
@limiter.limit("10/minute")
async def login_options(
    request: Request,
    body: PreAuthIn,
    conn: asyncpg.Connection = Depends(get_conn),
):
    user_id = uuid.UUID(verify_pre_auth_token(body.pre_auth_token))
    await _get_user_row(conn, user_id)

    creds = await conn.fetch(
        "SELECT credential_id FROM webauthn_credentials WHERE user_id=$1 AND credential_id IS NOT NULL AND credential_id <> '' AND public_key IS NOT NULL AND public_key <> ''", user_id,
    )
    if not creds:
        raise HTTPException(
            status.HTTP_428_PRECONDITION_REQUIRED,
            detail="No biometric device registered for this account. Set up Face ID/fingerprint to continue.",
        )

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(r["credential_id"]))
            for r in creds
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    await _store_challenge(conn, user_id, options.challenge, "authentication")
    return {"options": options_to_json(options)}


# -------------------------------------------------------------------------
# 4. Login verify — both factors now satisfied; issues the real session JWT,
#    same shape /auth/login used to return before this flow existed.
# -------------------------------------------------------------------------
@router.post("/login/verify", response_model=TokenOut)
@limiter.limit("10/minute")
async def login_verify(
    request: Request,
    body: AuthenticationVerifyIn,
    conn: asyncpg.Connection = Depends(get_conn),
):
    user_id = uuid.UUID(verify_pre_auth_token(body.pre_auth_token))
    user_row = await _get_user_row(conn, user_id)
    challenge = await _pop_challenge(conn, user_id, "authentication")

    cred_row = await conn.fetchrow(
        """
        SELECT credential_id, public_key, sign_count FROM webauthn_credentials
        WHERE user_id=$1 AND credential_id=$2
        """,
        user_id, body.credential.get("id"),
    )
    if not cred_row:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Unrecognized device")

    try:
        credential = parse_authentication_credential_json(_dict_to_json(body.credential))
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=EXPECTED_ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=base64url_to_bytes(cred_row["public_key"]),
            credential_current_sign_count=cred_row["sign_count"],
            require_user_verification=True,
        )
    except Exception as exc:
        logger.exception("WebAuthn authentication verify failed: %s", exc)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Could not verify this device's response")

    await conn.execute(
        "UPDATE webauthn_credentials SET sign_count=$1, last_used_at=now() WHERE credential_id=$2",
        verification.new_sign_count, cred_row["credential_id"],
    )

    user = {k: str(v) if isinstance(v, uuid.UUID) else v for k, v in dict(user_row).items()}
    user["permissions"] = resolve_permissions(user.get("role"), user.get("permissions"))
    token = create_access_token({"sub": str(user_id)})
    await write_audit(conn, "Staff Login", actor=user, detail=f"Biometric step verified: {user_row['email']}")
    return {"access_token": token, "token_type": "bearer", "user": user}


# --- small helpers --------------------------------------------------------
import base64
import json


def _bytes_to_b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _dict_to_json(d: dict) -> str:
    return json.dumps(d)
