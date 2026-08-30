"""
Badge Registry — full lifecycle audit trail of physical visit badges.

Only Admin, Super Admin and Receptionist may view it (Front Desk Security
and Room Guard are excluded, matching their restricted module access).

Each issuance appends a new row to `badges`, so the history here shows
every time a badge number was handed out, to whom, to which room, and
when it was returned (if ever).
"""

import asyncpg
from fastapi import APIRouter, Depends, Query

from database import get_conn
from models import UserRole
from utils.auth import require_roles

router = APIRouter(prefix="/badges", tags=["Badge Registry"])


@router.get("")
async def list_badges(
    status: str   = Query("all", description="all | active | returned"),
    q:      str   = Query("",   description="Search badge_number or visitor_name"),
    limit:  int   = Query(200, ge=1, le=1000),
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin, UserRole.recep)),
    conn:   asyncpg.Connection = Depends(get_conn),
):
    """Badge audit registry with status filter and keyword search."""
    if status not in ("all", "active", "returned"):
        status = "all"
    search = f"%{q}%" if q.strip() else None
    rows = await conn.fetch(
        """
        SELECT b.id, b.badge_number, b.status, b.issued_at, b.returned_at,
               b.visit_request_id, b.issued_by,
               s.name              AS issued_by_name,
               vr.visitor_name, vr.purpose, vr.host_name,
               p.id                AS post_id,
               p.name              AS room,
               p.restriction_level AS room_restriction_level
        FROM   badges b
        LEFT   JOIN staff_users s  ON s.id  = b.issued_by
        LEFT   JOIN visit_requests vr ON vr.id = b.visit_request_id
        LEFT   JOIN posts p        ON p.id  = vr.destination_post_id
        WHERE  ($1::text = 'all' OR b.status = $1::text)
          AND  ($2::text IS NULL
                OR b.badge_number    ILIKE $2
                OR vr.visitor_name   ILIKE $2)
        ORDER  BY b.issued_at DESC
        LIMIT  $3
        """,
        status, search, limit,
    )
    return [dict(r) for r in rows]