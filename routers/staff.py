"""
Staff management — Administrator-only.

Lets an admin:
  - see every staff account and which post (Security Desk, 1st Floor, etc.)
  - create a new staff/receptionist/guard account
  - assign or change someone's post
  - activate/deactivate an account

Note: this does NOT touch WebAuthn credentials. A newly created staff
member still goes through the normal first-login biometric enrollment
flow in routers/webauthn.py the first time they sign in.
"""

import json
import uuid

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr

from database import get_conn
from models import UserRole, ALL_MODULES, DEFAULT_MODULES_BY_ROLE
from utils.auth import get_current_user, require_roles, require_modules, hash_password, resolve_permissions
from utils.audit import write_audit

router = APIRouter(prefix="/staff", tags=["Staff Management"])


class StaffCreateIn(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: UserRole
    post_id: uuid.UUID | None = None
    department_id: uuid.UUID | None = None
    permissions: list[str] | None = None


class StaffUpdateIn(BaseModel):
    role: UserRole | None = None
    post_id: uuid.UUID | None = None
    department_id: uuid.UUID | None = None
    is_active: bool | None = None
    clear_post: bool = False
    clear_department: bool = False
    permissions: list[str] | None = None


def _initials(name: str) -> str:
    parts = [p for p in name.strip().split() if p]
    if not parts:
        return "??"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


def _permissions_for(role: str, requested: list[str] | None) -> list[str]:
    """Validate/derive a permissions list for a given role.

    - Super Admin is locked to the full default set (never customized).
    - If `requested` is provided it must only contain known modules;
      `dashboard` is force-included.
    - Otherwise fall back to the role's defaults.
    """
    if role == UserRole.super_admin.value:
        return list(DEFAULT_MODULES_BY_ROLE[role])
    if requested is None:
        return list(DEFAULT_MODULES_BY_ROLE.get(role, []))
    perms = [m for m in requested if m in ALL_MODULES]
    if "dashboard" not in perms:
        perms = ["dashboard"] + perms
    return perms


@router.get("")
async def list_staff(
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:      dict = Depends(require_modules("staff")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    rows = await conn.fetch(
        """
        SELECT su.id, su.name, su.initials, su.email, su.role, su.is_active,
               su.permissions,
               su.post_id, p.name AS post_name,
               su.department_id, d.name AS department_name
        FROM staff_users su
        LEFT JOIN posts p ON p.id = su.post_id
        LEFT JOIN departments d ON d.id = su.department_id
        ORDER BY p.name NULLS LAST, su.name
        """
    )
    result = []
    for r in rows:
        item = dict(r)
        item["permissions"] = resolve_permissions(item["role"], item.get("permissions"))
        result.append(item)
    return result


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_staff(
    body: StaffCreateIn,
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:    dict = Depends(require_modules("staff")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchval("SELECT 1 FROM staff_users WHERE email=$1", body.email.lower())
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="An account with this email already exists")

    if body.post_id is not None:
        post_exists = await conn.fetchval("SELECT 1 FROM posts WHERE id=$1", body.post_id)
        if not post_exists:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That post does not exist")

    if body.department_id is not None:
        dept_exists = await conn.fetchval("SELECT 1 FROM departments WHERE id=$1", body.department_id)
        if not dept_exists:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That department does not exist")

    permissions = _permissions_for(body.role.value, body.permissions)
    row = await conn.fetchrow(
        """
        INSERT INTO staff_users (name, initials, email, password_hash, role, is_active, post_id, department_id, permissions)
        VALUES ($1, $2, $3, $4, $5::user_role, true, $6, $7, $8::jsonb)
        RETURNING id, name, initials, email, role, is_active, post_id, department_id, permissions
        """,
        body.name, _initials(body.name), body.email.lower(),
        hash_password(body.password), body.role.value, body.post_id, body.department_id,
        json.dumps(permissions),
    )
    row = dict(row)
    row["permissions"] = resolve_permissions(row["role"], row.get("permissions"))
    await write_audit(conn, "Staff Created", actor=current, detail=f"Account created: {body.email} ({body.role.value})")
    return row


@router.patch("/{staff_id}")
async def update_staff(
    staff_id: uuid.UUID,
    body: StaffUpdateIn,
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:    dict = Depends(require_modules("staff")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    target = await conn.fetchrow("SELECT id, role, permissions FROM staff_users WHERE id=$1", staff_id)
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Staff member not found")

    if body.post_id is not None and not body.clear_post:
        post_exists = await conn.fetchval("SELECT 1 FROM posts WHERE id=$1", body.post_id)
        if not post_exists:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That post does not exist")

    if body.department_id is not None and not body.clear_department:
        dept_exists = await conn.fetchval("SELECT 1 FROM departments WHERE id=$1", body.department_id)
        if not dept_exists:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That department does not exist")

    new_post_id = None if body.clear_post else body.post_id
    new_dept_id = None if body.clear_department else body.department_id

    # Module permissions:
    #  - changing role resets access to the new role's defaults
    #  - explicit `permissions` (with unchanged role) replaces the set
    #  - otherwise keep whatever the account already has
    new_role = body.role.value if body.role else target["role"]
    if new_role != target["role"]:
        permissions = _permissions_for(new_role, None)
    elif body.permissions is not None:
        permissions = _permissions_for(new_role, body.permissions)
    else:
        permissions = None  # unchanged

    row = await conn.fetchrow(
        """
        UPDATE staff_users SET
            role          = COALESCE($2::user_role, role),
            is_active     = COALESCE($3, is_active),
            post_id       = CASE WHEN $4 THEN NULL WHEN $5::uuid IS NOT NULL THEN $5 ELSE post_id END,
            department_id = CASE WHEN $6 THEN NULL WHEN $7::uuid IS NOT NULL THEN $7 ELSE department_id END,
            permissions   = COALESCE($8::jsonb, permissions)
        WHERE id = $1
        RETURNING id, name, initials, email, role, is_active, post_id, department_id, permissions
        """,
        staff_id,
        new_role,
        body.is_active,
        body.clear_post,
        new_post_id,
        body.clear_department,
        new_dept_id,
        json.dumps(permissions) if permissions is not None else None,
    )
    row = dict(row)
    row["permissions"] = resolve_permissions(row["role"], row.get("permissions"))
    await write_audit(conn, "Staff Updated", actor=current, detail=f"Account updated: {row['email']}")
    return row


# ---------------------------------------------------------------------
# Posts (physical positions/locations staff can be assigned to)
# ---------------------------------------------------------------------
posts_router = APIRouter(prefix="/posts", tags=["Posts"])


class PostCreateIn(BaseModel):
    name: str
    description: str | None = None
    floor: int = 1
    pos_x: float = 0
    pos_y: float = 0
    width: float = 10
    height: float = 10


@posts_router.get("")
async def list_posts(
    current: dict = Depends(get_current_user),  # any logged-in staff can view posts
    conn: asyncpg.Connection = Depends(get_conn),
):
    rows = await conn.fetch(
        """
        SELECT p.id, p.name, p.description, p.floor, p.pos_x, p.pos_y, p.width, p.height,
               COUNT(su.id) AS assigned_count
        FROM posts p
        LEFT JOIN staff_users su ON su.post_id = p.id AND su.is_active
        GROUP BY p.id
        ORDER BY p.floor, p.name
        """
    )
    return [dict(r) for r in rows]


@posts_router.get("/{post_id}/detail")
async def post_detail(
    post_id: uuid.UUID,
    current: dict = Depends(get_current_user),  # any logged-in staff can view
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Everything an admin sees when clicking a room on the map: who's
    assigned there, and which visitors have arrived and not yet left."""
    post = await conn.fetchrow(
        "SELECT id, name, description, floor, pos_x, pos_y, width, height FROM posts WHERE id=$1",
        post_id,
    )
    if not post:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Room/post not found")

    guards = await conn.fetch(
        """
        SELECT id, name, initials, role
        FROM staff_users
        WHERE post_id = $1 AND is_active
        ORDER BY name
        """,
        post_id,
    )

    visitors_inside = await conn.fetch(
        """
        SELECT rv.id AS room_visit_id, rv.arrived_at,
               vr.id AS visit_request_id, vr.visitor_name, vr.host_name
        FROM room_visits rv
        JOIN visit_requests vr ON vr.id = rv.visit_request_id
        WHERE rv.post_id = $1 AND rv.departed_at IS NULL
        ORDER BY rv.arrived_at DESC
        """,
        post_id,
    )

    return {
        "post": dict(post),
        "assigned_staff": [dict(g) for g in guards],
        "visitors_inside": [dict(v) for v in visitors_inside],
    }


class ArrivalScanIn(BaseModel):
    badge_number: str


@posts_router.post("/{post_id}/lookup-badge")
async def lookup_badge(
    post_id: uuid.UUID,
    body: ArrivalScanIn,
    current: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Look up a badge without logging an arrival. Used by room guards to
    preview visitor details before confirming arrival."""
    badge = await conn.fetchrow(
        "SELECT last_issued_to FROM badges WHERE badge_number=$1 AND is_available=false",
        body.badge_number,
    )
    if not badge or not badge["last_issued_to"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Badge not recognized or not currently issued")

    visit = await conn.fetchrow(
        """
        SELECT id, visitor_name, visitor_email, company, phone, id_type, id_number,
               host_name, purpose, visit_date, expected_time, status, badge_number,
               destination_post_id
        FROM visit_requests WHERE id=$1
        """,
        badge["last_issued_to"],
    )
    if not visit:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No active visit found for this badge")

    is_correct_destination = visit["destination_post_id"] == post_id
    return {
        "visit_id": visit["id"],
        "visitor_name": visit["visitor_name"],
        "visitor_email": visit["visitor_email"],
        "company": visit["company"],
        "phone": visit["phone"],
        "id_type": visit["id_type"],
        "id_number": visit["id_number"],
        "host_name": visit["host_name"],
        "purpose": visit["purpose"],
        "visit_date": str(visit["visit_date"]) if visit["visit_date"] else None,
        "expected_time": str(visit["expected_time"]) if visit["expected_time"] else None,
        "status": visit["status"],
        "badge_number": visit["badge_number"],
        "is_correct_destination": is_correct_destination,
    }


@posts_router.post("/{post_id}/arrivals")
async def scan_arrival(
    post_id: uuid.UUID,
    body: ArrivalScanIn,
    current: dict = Depends(get_current_user),  # the guard doing the scan
    conn: asyncpg.Connection = Depends(get_conn),
):
    """A guard scans a visitor's badge at this room. Looks up the active
    visit that badge is issued to, logs an arrival, and flags a mismatch
    (without blocking it) if this isn't actually their assigned destination —
    guards can still admit someone off-route, but the system notes it."""
    badge = await conn.fetchrow(
        "SELECT last_issued_to FROM badges WHERE badge_number=$1 AND is_available=false",
        body.badge_number,
    )
    if not badge or not badge["last_issued_to"]:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Badge not recognized or not currently issued")

    visit = await conn.fetchrow(
        """
        SELECT id, visitor_name, visitor_email, company, phone, id_type, id_number,
               host_name, purpose, visit_date, expected_time, status, badge_number,
               destination_post_id
        FROM visit_requests WHERE id=$1
        """,
        badge["last_issued_to"],
    )
    if not visit:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No active visit found for this badge")

    row = await conn.fetchrow(
        """
        INSERT INTO room_visits (visit_request_id, post_id, scanned_by)
        VALUES ($1, $2, $3)
        RETURNING id, arrived_at
        """,
        visit["id"], post_id, current["id"],
    )
    await write_audit(conn, "Checked In", actor=current, visit_request_id=visit["id"], visitor_name=visit["visitor_name"])

    is_correct_destination = visit["destination_post_id"] == post_id
    return {
        "room_visit_id": row["id"],
        "arrived_at": row["arrived_at"],
        "visitor_name": visit["visitor_name"],
        "visitor_email": visit["visitor_email"],
        "company": visit["company"],
        "phone": visit["phone"],
        "id_type": visit["id_type"],
        "id_number": visit["id_number"],
        "host_name": visit["host_name"],
        "purpose": visit["purpose"],
        "visit_date": str(visit["visit_date"]) if visit["visit_date"] else None,
        "expected_time": str(visit["expected_time"]) if visit["expected_time"] else None,
        "status": visit["status"],
        "badge_number": visit["badge_number"],
        "is_correct_destination": is_correct_destination,
        "detail": "Arrival logged" if is_correct_destination else "Arrival logged — note: this is not this visitor's assigned destination",
    }


@posts_router.get("/{post_id}/recent-arrivals")
async def recent_arrivals(
    post_id: uuid.UUID,
    current: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Return recent arrivals at this post (last 50)."""
    rows = await conn.fetch(
        """
        SELECT rv.id AS room_visit_id, rv.arrived_at, rv.departed_at,
               vr.visitor_name, vr.visitor_email, vr.company, vr.host_name,
               vr.purpose, vr.badge_number, vr.visit_date
        FROM room_visits rv
        JOIN visit_requests vr ON rv.visit_request_id = vr.id
        WHERE rv.post_id = $1
        ORDER BY rv.arrived_at DESC
        LIMIT 50
        """,
        post_id,
    )
    return [dict(r) for r in rows]


@posts_router.post("", status_code=status.HTTP_201_CREATED)
async def create_post(
    body: PostCreateIn,
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:    dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchval("SELECT 1 FROM posts WHERE name=$1", body.name)
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A post with this name already exists")
    row = await conn.fetchrow(
        """
        INSERT INTO posts (name, description, floor, pos_x, pos_y, width, height)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, name, description, floor, pos_x, pos_y, width, height
        """,
        body.name, body.description, body.floor, body.pos_x, body.pos_y, body.width, body.height,
    )
    return dict(row)


class PostUpdateIn(BaseModel):
    pos_x: float | None = None
    pos_y: float | None = None
    width: float | None = None
    height: float | None = None
    name: str | None = None
    description: str | None = None
    floor: int | None = None


@posts_router.patch("/{post_id}")
async def update_post(
    post_id: uuid.UUID,
    body: PostUpdateIn,
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:    dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchrow("SELECT id FROM posts WHERE id=$1", post_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Post not found")

    row = await conn.fetchrow(
        """
        UPDATE posts SET
            pos_x       = COALESCE($2, pos_x),
            pos_y       = COALESCE($3, pos_y),
            width       = COALESCE($4, width),
            height      = COALESCE($5, height),
            name        = COALESCE($6, name),
            description = COALESCE($7, description),
            floor       = COALESCE($8, floor)
        WHERE id = $1
        RETURNING id, name, description, floor, pos_x, pos_y, width, height
        """,
        post_id,
        body.pos_x, body.pos_y, body.width, body.height,
        body.name, body.description, body.floor,
    )
    return dict(row)
