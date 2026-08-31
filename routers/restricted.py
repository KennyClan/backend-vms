"""
Restricted Areas — full CRUD + access workflow.

Flow:
  1. Admin/Receptionist creates a restricted area  (POST /restricted-areas)
  2. Admin grants a visitor restricted access       (POST /restricted-areas/{area_id}/grant)
  3. Guard scans visitor's approval QR, issues
     a special restricted badge                     (POST /restricted-areas/badge/issue)
  4. Second guard at the entrance scans the badge
     to confirm the visitor entered the area        (POST /restricted-areas/badge/confirm-entry)
  5. Guard confirms exit                            (POST /restricted-areas/badge/confirm-exit)
  6. Admin views who is currently inside            (GET  /restricted-areas/{area_id}/occupants)
"""

import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from typing import Optional
import asyncpg

from database import get_conn
from models import UserRole
from utils.auth import require_roles, get_current_user, require_modules
from utils.audit import write_audit

router = APIRouter(prefix="/restricted-areas", tags=["Restricted Areas"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class AreaIn(BaseModel):
    name:        str
    description: Optional[str] = None
    floor:       Optional[str] = None

class GrantIn(BaseModel):
    visit_request_id: uuid.UUID

class IssueBadgeIn(BaseModel):
    """Guard scans approval QR (qr_ref) and assigns a restricted badge number."""
    qr_ref:             str
    restricted_area_id: uuid.UUID
    restricted_badge:   str   # guard types e.g. "RA-1024"

class BadgeScanIn(BaseModel):
    """Guard at area entrance scans the restricted badge to confirm entry."""
    restricted_badge: str

class ExitScanIn(BaseModel):
    """Guard scans restricted badge on exit."""
    restricted_badge: str


# ── Area management ──────────────────────────────────────────────────────────

@router.get("")
async def list_areas(
    current: dict               = Depends(get_current_user),
    _m:      dict               = Depends(require_modules("restricted")),
    conn:    asyncpg.Connection = Depends(get_conn),
):
    rows = await conn.fetch(
        """
        SELECT ra.*, s.name AS created_by_name,
               COUNT(rac.id) FILTER (WHERE rac.status = 'Inside') AS current_occupants
        FROM   restricted_areas ra
        LEFT   JOIN staff_users s   ON s.id  = ra.created_by
        LEFT   JOIN restricted_access rac ON rac.restricted_area_id = ra.id
        WHERE  ra.is_active = TRUE
        GROUP  BY ra.id, s.name
        ORDER  BY ra.created_at DESC
        """
    )
    return [dict(r) for r in rows]


@router.post("", status_code=201)
async def create_area(
    body:    AreaIn,
    current: dict               = Depends(require_roles(UserRole.admin, UserRole.super_admin, UserRole.recep)),
    _m:      dict               = Depends(require_modules("restricted")),
    conn:    asyncpg.Connection = Depends(get_conn),
):
    # Floor plan objects default to a generic name ("Room", "Restricted")
    # unless the user renames them, so collisions here are common and
    # shouldn't block the auto-create-from-floor-plan flow. If the name is
    # already taken, keep appending " (2)", " (3)", etc. until it isn't.
    name = body.name
    suffix = 1
    while True:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO restricted_areas (name, description, floor, created_by)
                VALUES ($1, $2, $3, $4) RETURNING *
                """,
                name, body.description, body.floor, uuid.UUID(str(current["id"])),
            )
            break
        except asyncpg.UniqueViolationError:
            suffix += 1
            name = f"{body.name} ({suffix})"
            if suffix > 50:  # sanity guard against an infinite loop
                raise HTTPException(400, "An area with this name already exists.")
    await write_audit(conn, "Restricted Area Created", actor=current, detail=f"Area: {body.name}")
    return dict(row)


@router.delete("/{area_id}")
async def deactivate_area(
    area_id: uuid.UUID,
    current: dict               = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict               = Depends(require_modules("restricted")),
    conn:    asyncpg.Connection = Depends(get_conn),
):
    await conn.execute(
        "UPDATE restricted_areas SET is_active=FALSE WHERE id=$1", area_id
    )
    await write_audit(conn, "Restricted Area Deactivated", actor=current, detail=str(area_id))
    return {"ok": True}


# ── Access grant (Admin only) ─────────────────────────────────────────────────

@router.post("/{area_id}/grant", status_code=201)
async def grant_access(
    area_id: uuid.UUID,
    body:    GrantIn,
    current: dict               = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict               = Depends(require_modules("restricted")),
    conn:    asyncpg.Connection = Depends(get_conn),
):
    # Verify the visit request is approved
    req = await conn.fetchrow(
        "SELECT * FROM visit_requests WHERE id=$1", body.visit_request_id
    )
    if not req:
        raise HTTPException(404, "Visit request not found.")
    if req["approval_status"] != "Approved":
        raise HTTPException(400, "Visit request must be approved before granting restricted access.")

    # Prevent duplicate grants
    exists = await conn.fetchval(
        "SELECT EXISTS(SELECT 1 FROM restricted_access WHERE visit_request_id=$1 AND restricted_area_id=$2)",
        body.visit_request_id, area_id,
    )
    if exists:
        raise HTTPException(400, "Access already granted for this visitor to this area.")

    row = await conn.fetchrow(
        """
        INSERT INTO restricted_access
          (visit_request_id, restricted_area_id, restricted_badge, approved_by, approved_at)
        VALUES ($1, $2, $3, $4, $5) RETURNING *
        """,
        body.visit_request_id,
        area_id,
        "",   # badge assigned later by the guard
        uuid.UUID(str(current["id"])),
        datetime.now(timezone.utc),
    )
    area = await conn.fetchrow("SELECT name FROM restricted_areas WHERE id=$1", area_id)
    await write_audit(
        conn, "Restricted Access Granted", actor=current,
        visit_request_id=body.visit_request_id,
        visitor_name=req["visitor_name"],
        detail=f"Area: {area['name']}",
    )
    return dict(row)


# ── Guard: issue restricted badge ─────────────────────────────────────────────

@router.post("/badge/issue")
async def issue_badge(
    body:    IssueBadgeIn,
    current: dict               = Depends(require_roles(UserRole.admin, UserRole.super_admin, UserRole.recep, UserRole.guard)),
    _m:      dict               = Depends(require_modules("security")),
    conn:    asyncpg.Connection = Depends(get_conn),
):
    # Look up visit request by QR ref
    req = await conn.fetchrow(
        "SELECT * FROM visit_requests WHERE qr_ref=$1", body.qr_ref
    )
    if not req:
        raise HTTPException(404, "QR code not found.")
    if req["approval_status"] != "Approved":
        raise HTTPException(400, "This visitor's request has not been approved.")

    # Find the restricted access grant
    access = await conn.fetchrow(
        """
        SELECT * FROM restricted_access
        WHERE visit_request_id=$1 AND restricted_area_id=$2
        """,
        req["id"], body.restricted_area_id,
    )
    if not access:
        # Auto-create the grant for visitors destined for a restricted area
        # (derived from the host's department). Covers the Security Desk flow
        # where the restriction is recognised from the request before any
        # manual admin grant row exists.
        area_ok = await conn.fetchval(
            """SELECT 1
               FROM staff_users su
               JOIN departments d ON d.id = su.department_id
               WHERE su.id = $1 AND d.is_restricted = TRUE
                 AND d.restricted_area_id = $2""",
            req["host_staff_id"], body.restricted_area_id,
        )
        if req["destination_type"] != "Restricted" or not area_ok:
            raise HTTPException(404, "No restricted access grant found for this visitor and area.")
        access = await conn.fetchrow(
            """
            INSERT INTO restricted_access (visit_request_id, restricted_area_id, restricted_badge)
            VALUES ($1, $2, '') RETURNING *
            """,
            req["id"], body.restricted_area_id,
        )
    if access["status"] not in ("Pending",):
        raise HTTPException(400, f"Badge already issued (status: {access['status']}).")

    # Check badge number not already in use
    taken = await conn.fetchval(
        "SELECT EXISTS(SELECT 1 FROM restricted_access WHERE restricted_badge=$1)", body.restricted_badge
    )
    if taken:
        raise HTTPException(400, "This badge number is already assigned to another visitor.")

    updated = await conn.fetchrow(
        """
        UPDATE restricted_access
        SET restricted_badge=$1, badge_issued_by=$2, badge_issued_at=$3, status='Badge Issued'
        WHERE id=$4 RETURNING *
        """,
        body.restricted_badge,
        uuid.UUID(str(current["id"])),
        datetime.now(timezone.utc),
        access["id"],
    )
    area = await conn.fetchrow("SELECT name FROM restricted_areas WHERE id=$1", body.restricted_area_id)
    await write_audit(
        conn, "Restricted Badge Issued", actor=current,
        visit_request_id=req["id"],
        visitor_name=req["visitor_name"],
        detail=f"Badge {body.restricted_badge} → Area: {area['name']}",
    )
    return {**dict(updated), "visitor_name": req["visitor_name"], "area_name": area["name"]}


# ── Guard at entrance: scan badge to confirm entry ───────────────────────────

@router.post("/badge/confirm-entry")
async def confirm_entry(
    body:    BadgeScanIn,
    current: dict               = Depends(require_roles(UserRole.admin, UserRole.super_admin, UserRole.recep)),
    _m:      dict               = Depends(require_modules("restricted")),
    conn:    asyncpg.Connection = Depends(get_conn),
):
    access = await conn.fetchrow(
        "SELECT * FROM restricted_access WHERE restricted_badge=$1", body.restricted_badge
    )
    if not access:
        raise HTTPException(404, "Badge not found. Check the badge number.")
    if access["status"] != "Badge Issued":
        raise HTTPException(400, f"Cannot confirm entry — current status is '{access['status']}'.")

    req   = await conn.fetchrow("SELECT * FROM visit_requests WHERE id=$1", access["visit_request_id"])
    area  = await conn.fetchrow("SELECT name FROM restricted_areas WHERE id=$1", access["restricted_area_id"])

    await conn.execute(
        """
        UPDATE restricted_access
        SET entry_confirmed_by=$1, entry_confirmed_at=$2, status='Inside'
        WHERE id=$3
        """,
        uuid.UUID(str(current["id"])),
        datetime.now(timezone.utc),
        access["id"],
    )
    await write_audit(
        conn, "Restricted Area Entry Confirmed", actor=current,
        visit_request_id=req["id"],
        visitor_name=req["visitor_name"],
        detail=f"Badge {body.restricted_badge} entered {area['name']}",
    )
    return {"visitor_name": req["visitor_name"], "area_name": area["name"], "status": "Inside"}


# ── Guard: confirm exit ───────────────────────────────────────────────────────

@router.post("/badge/confirm-exit")
async def confirm_exit(
    body:    ExitScanIn,
    current: dict               = Depends(require_roles(UserRole.admin, UserRole.super_admin, UserRole.recep)),
    _m:      dict               = Depends(require_modules("restricted")),
    conn:    asyncpg.Connection = Depends(get_conn),
):
    access = await conn.fetchrow(
        "SELECT * FROM restricted_access WHERE restricted_badge=$1", body.restricted_badge
    )
    if not access:
        raise HTTPException(404, "Badge not found.")
    if access["status"] != "Inside":
        raise HTTPException(400, f"Cannot confirm exit — current status is '{access['status']}'.")

    req  = await conn.fetchrow("SELECT * FROM visit_requests WHERE id=$1", access["visit_request_id"])
    area = await conn.fetchrow("SELECT name FROM restricted_areas WHERE id=$1", access["restricted_area_id"])

    await conn.execute(
        "UPDATE restricted_access SET exited_at=$1, status='Exited' WHERE id=$2",
        datetime.now(timezone.utc), access["id"],
    )
    await write_audit(
        conn, "Restricted Area Exit", actor=current,
        visit_request_id=req["id"],
        visitor_name=req["visitor_name"],
        detail=f"Badge {body.restricted_badge} exited {area['name']}",
    )
    return {"visitor_name": req["visitor_name"], "area_name": area["name"], "status": "Exited"}


# ── Admin: who is currently inside a specific area ────────────────────────────

@router.get("/{area_id}/occupants")
async def list_occupants(
    area_id: uuid.UUID,
    current: dict               = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict               = Depends(require_modules("restricted")),
    conn:    asyncpg.Connection = Depends(get_conn),
):
    rows = await conn.fetch(
        """
        SELECT rac.*, vr.visitor_name, vr.purpose, vr.host_name,
               s1.name AS approved_by_name,
               s2.name AS badge_issued_by_name,
               s3.name AS entry_confirmed_by_name
        FROM   restricted_access rac
        JOIN   visit_requests vr ON vr.id = rac.visit_request_id
        LEFT   JOIN staff_users s1 ON s1.id = rac.approved_by
        LEFT   JOIN staff_users s2 ON s2.id = rac.badge_issued_by
        LEFT   JOIN staff_users s3 ON s3.id = rac.entry_confirmed_by
        WHERE  rac.restricted_area_id = $1
        ORDER  BY rac.entry_confirmed_at DESC NULLS LAST
        """,
        area_id,
    )
    return [dict(r) for r in rows]
