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
               su.post_id, p.name AS post_name, p.room_number AS post_room_number,
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


@router.get("/me")
async def get_staff_me(
    current: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """The calling staff member's own record (post + department). Room Guard's
    My Room page needs this — guards are blocked from the admin-only GET /staff
    list, so without it they can never load their assignment."""
    row = await conn.fetchrow(
        """
        SELECT su.id, su.name, su.initials, su.email, su.role, su.is_active,
               su.post_id, p.name AS post_name, p.room_number AS post_room_number,
               su.department_id, d.name AS department_name
        FROM staff_users su
        LEFT JOIN posts p ON p.id = su.post_id
        LEFT JOIN departments d ON d.id = su.department_id
        WHERE su.id = $1
        """,
        current["id"],
    )
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Staff record not found")
    item = dict(row)
    item["permissions"] = resolve_permissions(item["role"], item.get("permissions"))
    return item


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

    is_guard = body.role.value == UserRole.guard.value

    # Department owns the room: the staff member's room IS their department's
    # room — there is no independent room picker anymore.
    dept = None
    if body.department_id is not None:
        dept = await conn.fetchrow(
            "SELECT id, name, post_id FROM departments WHERE id=$1", body.department_id
        )
        if not dept:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That department does not exist")

    if is_guard:
        if dept is None or dept["post_id"] is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "A Security Guard must belong to a department whose room is linked — "
                "one department = one room = one guard (link the room in Departments first).",
            )

    derived_post_id = dept["post_id"] if dept is not None else body.post_id

    if is_guard:
        occupant = await conn.fetchrow(
            "SELECT id, name FROM staff_users WHERE post_id=$1 AND role='Security Guard' AND is_active",
            derived_post_id,
        )
        if occupant:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"This room already has an active guard ({occupant['name']}). "
                "Reassign or deactivate them before assigning another guard here.",
            )

    permissions = _permissions_for(body.role.value, body.permissions)
    row = await conn.fetchrow(
        """
        INSERT INTO staff_users (name, initials, email, password_hash, role, is_active, post_id, department_id, permissions)
        VALUES ($1, $2, $3, $4, $5::user_role, true, $6, $7, $8::jsonb)
        RETURNING id, name, initials, email, role, is_active, post_id, department_id, permissions
        """,
        body.name, _initials(body.name), body.email.lower(),
        hash_password(body.password), body.role.value, derived_post_id, body.department_id,
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
    target = await conn.fetchrow(
        "SELECT id, name, role, permissions, post_id, department_id FROM staff_users WHERE id=$1", staff_id
    )
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Staff member not found")

    if body.post_id is not None:
        post_exists = await conn.fetchval("SELECT 1 FROM posts WHERE id=$1", body.post_id)
        if not post_exists:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That post does not exist")

    new_role = body.role.value if body.role else target["role"]
    is_guard = new_role == UserRole.guard.value

    # Resolve the department (explicit change > current).
    if body.clear_department:
        dept = None
    elif body.department_id is not None:
        dept = await conn.fetchrow(
            "SELECT id, name, post_id FROM departments WHERE id=$1", body.department_id
        )
        if not dept:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That department does not exist")
    elif target["department_id"]:
        dept = await conn.fetchrow(
            "SELECT id, name, post_id FROM departments WHERE id=$1", target["department_id"]
        )
    else:
        dept = None

    if body.clear_department and is_guard:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "A Security Guard must belong to a department — its room is the guard's post.",
        )

    # Department owns the room: a staff member's room is their department's
    # room (one department = one room = one guard). No independent post.
    if dept is not None:
        new_post_id = dept["post_id"]
        new_dept_id = dept["id"]
    else:
        new_post_id = None if body.clear_post else (body.post_id or target["post_id"])  # legacy manual post
        new_dept_id = None

    if is_guard and new_post_id is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "A Security Guard must belong to a department whose room is linked — "
            "one department = one room = one guard (link the room in Departments first).",
        )

    if is_guard:
        occupant = await conn.fetchrow(
            "SELECT id, name FROM staff_users "
            "WHERE post_id=$1 AND role='Security Guard' AND is_active AND id != $2",
            new_post_id, staff_id,
        )
        if occupant:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"This room already has an active guard ({occupant['name']}). "
                "Reassign or deactivate them before assigning another guard here.",
            )

    # Module permissions:
    #  - changing role resets access to the new role's defaults
    #  - explicit `permissions` (with unchanged role) replaces the set
    #  - otherwise keep whatever the account already has
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
            post_id       = $4::uuid,
            department_id = $5::uuid,
            permissions   = COALESCE($6::jsonb, permissions)
        WHERE id = $1
        RETURNING id, name, initials, email, role, is_active, post_id, department_id, permissions
        """,
        staff_id,
        new_role,
        body.is_active,
        new_post_id,
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
               p.capacity, p.restriction_level, p.room_number,
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
        "SELECT id, name, description, floor, pos_x, pos_y, width, height, capacity, restriction_level, room_number FROM posts WHERE id=$1",
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

    last_scan = await conn.fetchrow(
        """
        SELECT rv.arrived_at, rv.departed_at,
               su.name AS scanned_by_name, su.role AS scanned_by_role
        FROM room_visits rv
        LEFT JOIN staff_users su ON su.id = rv.scanned_by
        WHERE rv.post_id = $1
        ORDER BY rv.arrived_at DESC
        LIMIT 1
        """,
        post_id,
    )

    return {
        "post": dict(post),
        "assigned_staff": [dict(g) for g in guards],
        "visitors_inside": [dict(v) for v in visitors_inside],
        "last_scan": dict(last_scan) if last_scan else None,
    }


class ArrivalScanIn(BaseModel):
    badge_number: str
    id_verified: bool = False
    photo_captured: bool = False
    photo: str | None = None


class DepartureScanIn(BaseModel):
    badge_number: str


async def _lookup_active_badge(conn: asyncpg.Connection, badge_number: str):
    """Resolve a live physical badge to its visit request (new badges schema:
    badge_number -> visit_request_id, status active/returned)."""
    badge = await conn.fetchrow(
        "SELECT visit_request_id FROM badges WHERE badge_number=$1 AND status='active'",
        badge_number,
    )
    if not badge:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="Badge not recognized or not currently issued",
        )
    return badge["visit_request_id"]


async def _check_guard_room_access(post_id: uuid.UUID, current: dict):
    """Enforce that only a Room Guard (or Super Admin) scans badges, and only
    at the room they are assigned to (staff_users.post_id)."""
    if current["role"] not in (UserRole.super_admin.value, UserRole.guard.value):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Only a Room Guard can scan badges at a room",
        )
    if current.get("post_id") != post_id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "You are not assigned to this room. Scan rejected.",
        )


@posts_router.post("/{post_id}/lookup-badge")
async def lookup_badge(
    post_id: uuid.UUID,
    body: ArrivalScanIn,
    current: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Look up a badge without logging an arrival. Used by room guards to
    preview visitor details before confirming arrival."""
    await _check_guard_room_access(post_id, current)
    visit_id = await _lookup_active_badge(conn, body.badge_number)

    visit = await conn.fetchrow(
        """
        SELECT id, visitor_name, visitor_email, company, phone, id_type, id_number,
               host_name, purpose, visit_date, expected_time, status, badge_number,
               destination_post_id
        FROM visit_requests WHERE id=$1
        """,
        visit_id,
    )
    if not visit:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No active visit found for this badge")

    is_correct_destination = visit["destination_post_id"] == post_id
    destination_name = None
    if visit["destination_post_id"]:
        dest = await conn.fetchrow(
            "SELECT name, room_number FROM posts WHERE id=$1", visit["destination_post_id"]
        )
        destination_name = _room_label_from_row(dest) if dest else None
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
        "destination_name": destination_name,
    }


def _room_label_from_row(row) -> str:
    if not row or not row.get("name"):
        return "this room"
    return f"{row['name']} ({row.get('room_number')})" if row.get("room_number") else row["name"]


@posts_router.post("/{post_id}/arrivals")
async def scan_arrival(
    post_id: uuid.UUID,
    body: ArrivalScanIn,
    current: dict = Depends(get_current_user),  # the Room Guard doing the scan
    conn: asyncpg.Connection = Depends(get_conn),
):
    """ROOM GUARD scan (department room, not front desk): the guard runs
    their assigned ROOM's badge over the scanner and the system logs that
    the visitor has physically arrived at that room.

    The badge was already issued by the Front Desk at the building entrance
    (badges.badge_number -> the active visit). This endpoint enforces the
    one-guard-one-room rule:
      1. badge_number resolves to the live visit
      2. the visit's assigned destination MUST be this guard's room —
         a badge headed to another department's room (e.g. HR when this is
         IT) is REJECTED, not silently admitted
      3. arrival is logged against THIS post + THIS guard (scanned_by),
         which also flips the visitor's wayfinding link to "arrived"
    """
    await _check_guard_room_access(post_id, current)
    visit_id = await _lookup_active_badge(conn, body.badge_number)

    visit = await conn.fetchrow(
        """
        SELECT id, visitor_name, visitor_email, company, phone, id_type, id_number,
               host_name, purpose, visit_date, expected_time, status, badge_number,
               destination_post_id
        FROM visit_requests WHERE id=$1
        """,
        visit_id,
    )
    if not visit:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No active visit found for this badge")

    # Room Guards only admit visitors whose assigned destination IS their
    # room. Two rooms can never share a guard's scan (one dept = one room =
    # one guard — enforced two layers down by DB unique indexes too).
    if visit["destination_post_id"] != post_id:
        dest_name = None
        if visit["destination_post_id"]:
            dest = await conn.fetchrow(
                "SELECT name, room_number FROM posts WHERE id=$1", visit["destination_post_id"]
            )
            dest_name = dest["name"] if dest else None
        room = await conn.fetchrow("SELECT name, room_number FROM posts WHERE id=$1", post_id)
        here = _room_label_from_row(room)
        if dest_name:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Badge {body.badge_number} belongs to {visit['visitor_name']}, who is assigned to "
                f"\"{dest_name}\" — this is {here}. Route them to their assigned destination room.",
            )
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Badge {body.badge_number} ({visit['visitor_name']}) has no room destination assigned "
            f"— that visitor belongs at the Front Desk, not a department room.",
        )

    # Room restriction level gates what the guard must complete first.
    #   none             -> scan only, no checklist
    #   restricted       -> ID must be verified
    #   highly_restricted-> ID verified AND a real photo must be attached
    post = await conn.fetchrow(
        "SELECT restriction_level, name FROM posts WHERE id=$1", post_id
    )
    if not post:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Room/post not found")
    level = post["restriction_level"]
    if level in ("restricted", "highly_restricted") and not body.id_verified:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Valid ID must be verified by the guard before entry to {post['name']}",
        )
    if level == "highly_restricted" and not (body.photo_captured and body.photo):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "A photo of the visitor is required before entry to this highly restricted room",
        )

    already = await conn.fetchval(
        """SELECT 1 FROM room_visits
           WHERE visit_request_id=$1 AND post_id=$2 AND departed_at IS NULL""",
        visit["id"], post_id,
    )
    if already:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Visitor is already inside this room")

    row = await conn.fetchrow(
        """
        INSERT INTO room_visits (visit_request_id, post_id, scanned_by, id_verified, photo_captured, photo)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, arrived_at
        """,
        visit["id"], post_id, current["id"], body.id_verified, body.photo_captured, body.photo,
    )
    await write_audit(conn, "Room Arrival", actor=current, visit_request_id=visit["id"], visitor_name=visit["visitor_name"])

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
        "detail": f"Visitor arrived at {_room_label_from_row(post)}",
    }


@posts_router.post("/{post_id}/departures")
async def scan_departure(
    post_id: uuid.UUID,
    body: DepartureScanIn,
    current: dict = Depends(get_current_user),  # the guard doing the scan
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Room guard checks a visitor out of a room by scanning their badge.
    Marks the active room_visits row departed, which decrements the room's
    live occupancy (counted from nondeparted rows) — satisfying the real-time
    capacity model without a mutable counter that could race."""
    await _check_guard_room_access(post_id, current)
    visit_id = await _lookup_active_badge(conn, body.badge_number)

    rv = await conn.fetchrow(
        """SELECT id FROM room_visits
           WHERE post_id=$1 AND visit_request_id=$2 AND departed_at IS NULL
           ORDER BY arrived_at DESC LIMIT 1""",
        post_id, visit_id,
    )
    if not rv:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="No active arrival found for this badge at this room",
        )
    await conn.execute(
        "UPDATE room_visits SET departed_at=NOW() WHERE id=$1", rv["id"]
    )
    visit = await conn.fetchrow(
        "SELECT visitor_name FROM visit_requests WHERE id=$1", visit_id
    )
    await write_audit(conn, "Room Departure", actor=current, visit_request_id=visit_id,
                      visitor_name=visit["visitor_name"] if visit else None,
                      detail="Room departure scan")
    return {"room_visit_id": rv["id"], "detail": "Departure logged"}


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
    capacity: int | None = None
    restriction_level: str | None = None


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
    if body.restriction_level and body.restriction_level not in ("none", "restricted", "highly_restricted"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="restriction_level must be one of: none, restricted, highly_restricted")

    row = await conn.fetchrow(
        """
        UPDATE posts SET
            pos_x            = COALESCE($2, pos_x),
            pos_y            = COALESCE($3, pos_y),
            width            = COALESCE($4, width),
            height           = COALESCE($5, height),
            name             = COALESCE($6, name),
            description      = COALESCE($7, description),
            floor            = COALESCE($8, floor),
            capacity         = COALESCE($9, capacity),
            restriction_level= COALESCE($10, restriction_level)
        WHERE id = $1
        RETURNING id, name, description, floor, pos_x, pos_y, width, height, capacity, restriction_level
        """,
        post_id,
        body.pos_x, body.pos_y, body.width, body.height,
        body.name, body.description, body.floor, body.capacity, body.restriction_level,
    )
    return dict(row)
