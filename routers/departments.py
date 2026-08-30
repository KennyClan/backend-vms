"""
Departments management — Administrator / Super Admin.

A Department groups staff users and can be flagged as restricted.
When restricted, it links to a Restricted Area (from the floor plan),
and all visit requests to employees in that department are auto-tagged
as destination_type = "Restricted".
"""

import uuid
from typing import Optional

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from database import get_conn
from models import UserRole
from utils.auth import require_roles, require_modules
from utils.audit import write_audit

router = APIRouter(prefix="/departments", tags=["Departments"])


class DepartmentCreateIn(BaseModel):
    name: str
    description: Optional[str] = None
    is_restricted: bool = False
    restricted_area_id: Optional[uuid.UUID] = None
    post_id: Optional[uuid.UUID] = None


class DepartmentUpdateIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_restricted: Optional[bool] = None
    restricted_area_id: Optional[uuid.UUID] = None
    post_id: Optional[uuid.UUID] = None
    clear_post: bool = False


async def _validate_room_link(conn: asyncpg.Connection, post_id: uuid.UUID | None, exclude_dept_id: uuid.UUID | None):
    """A room can only belong to ONE department (one department = one room)."""
    if post_id is None:
        return
    post_exists = await conn.fetchval("SELECT 1 FROM posts WHERE id=$1", post_id)
    if not post_exists:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="The specified room does not exist")
    other = await conn.fetchval(
        "SELECT 1 FROM departments WHERE post_id=$1 AND id != COALESCE($2, '00000000-0000-0000-0000-000000000000'::uuid)",
        post_id, exclude_dept_id,
    )
    if other:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This room is already linked to another department — a room can only belong to one department.",
        )


@router.get("")
async def list_departments(
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:      dict = Depends(require_modules("departments")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    rows = await conn.fetch(
        """
        SELECT d.id, d.name, d.description, d.is_restricted,
               d.restricted_area_id, d.post_id, d.created_at,
               ra.name AS restricted_area_name,
               p.name AS post_name, p.room_number AS post_room_number,
               COUNT(su.id) AS member_count
        FROM departments d
        LEFT JOIN restricted_areas ra ON ra.id = d.restricted_area_id
        LEFT JOIN posts p ON p.id = d.post_id
        LEFT JOIN staff_users su ON su.department_id = d.id AND su.is_active
        GROUP BY d.id, ra.name, p.name, p.room_number
        ORDER BY d.name
        """
    )
    return [dict(r) for r in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_department(
    body: DepartmentCreateIn,
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:      dict = Depends(require_modules("departments")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchval("SELECT 1 FROM departments WHERE name=$1", body.name)
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A department with this name already exists")

    if body.is_restricted and not body.restricted_area_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="A restricted department must be linked to a restricted area")

    if body.restricted_area_id:
        area_exists = await conn.fetchval("SELECT 1 FROM restricted_areas WHERE id=$1", body.restricted_area_id)
        if not area_exists:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="The specified restricted area does not exist")

    await _validate_room_link(conn, body.post_id, None)

    row = await conn.fetchrow(
        """
        INSERT INTO departments (name, description, is_restricted, restricted_area_id, post_id)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, name, description, is_restricted, restricted_area_id, post_id, created_at
        """,
        body.name, body.description, body.is_restricted, body.restricted_area_id, body.post_id,
    )
    await write_audit(conn, "Department Created", actor=current, detail=f"Department created: {body.name}")
    return dict(row)


@router.patch("/{department_id}")
async def update_department(
    department_id: uuid.UUID,
    body: DepartmentUpdateIn,
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:      dict = Depends(require_modules("departments")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchrow("SELECT * FROM departments WHERE id=$1", department_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Department not found")

    if body.name:
        name_taken = await conn.fetchval("SELECT 1 FROM departments WHERE name=$1 AND id!=$2", body.name, department_id)
        if name_taken:
            raise HTTPException(status.HTTP_409_CONFLICT, detail="A department with this name already exists")

    new_post_id = None if body.clear_post else body.post_id  # None here = leave unchanged
    await _validate_room_link(conn, new_post_id, department_id)
    if body.clear_post:
        new_post_id = None
    elif new_post_id is None:
        new_post_id = existing["post_id"]

    new_restricted_area = existing["restricted_area_id"] if body.restricted_area_id is None else body.restricted_area_id
    new_is_restricted = existing["is_restricted"] if body.is_restricted is None else body.is_restricted
    if new_is_restricted and not new_restricted_area:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="A restricted department must be linked to a restricted area")

    new_name = body.name if body.name else existing["name"]
    new_description = existing["description"] if body.description is None else body.description

    try:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                UPDATE departments SET
                    name              = $2,
                    description       = $3,
                    is_restricted     = $4,
                    restricted_area_id= $5,
                    post_id           = $6
                WHERE id = $1
                RETURNING id, name, description, is_restricted, restricted_area_id, post_id, created_at
                """,
                department_id, new_name, new_description, new_is_restricted,
                new_restricted_area, new_post_id,
            )
            # Room follows the department: re-point every member onto the new room
            # (or drop their room when the department is unlinked).
            if new_post_id is not None:
                await conn.execute(
                    "UPDATE staff_users SET post_id=$2 WHERE department_id=$1 AND post_id IS DISTINCT FROM $2",
                    department_id, new_post_id,
                )
            else:
                await conn.execute(
                    "UPDATE staff_users SET post_id=NULL WHERE department_id=$1 AND post_id IS NOT NULL",
                    department_id,
                )
    except asyncpg.exceptions.UniqueViolationError:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "That room already has an active Security Guard — reassign or deactivate them first.",
        )

    await write_audit(conn, "Department Updated", actor=current, detail=f"Department updated: {row['name']}")
    return dict(row)


@router.delete("/{department_id}")
async def delete_department(
    department_id: uuid.UUID,
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:      dict = Depends(require_modules("departments")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchrow("SELECT id, name FROM departments WHERE id=$1", department_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Department not found")

    member_count = await conn.fetchval("SELECT COUNT(*) FROM staff_users WHERE department_id=$1", department_id)
    if member_count > 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Cannot delete department with {member_count} member(s). Reassign them first.")

    await conn.execute("DELETE FROM departments WHERE id=$1", department_id)
    await write_audit(conn, "Department Deleted", actor=current, detail=f"Department deleted: {existing['name']}")
    return {"detail": f"Department '{existing['name']}' deleted"}


@router.get("/{department_id}/members")
async def list_department_members(
    department_id: uuid.UUID,
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:      dict = Depends(require_modules("departments")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    dept = await conn.fetchrow("SELECT id FROM departments WHERE id=$1", department_id)
    if not dept:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Department not found")

    rows = await conn.fetch(
        """
        SELECT su.id, su.name, su.initials, su.email, su.role, su.is_active
        FROM staff_users su
        WHERE su.department_id = $1
        ORDER BY su.name
        """,
        department_id,
    )
    return [dict(r) for r in rows]
