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


class DepartmentUpdateIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_restricted: Optional[bool] = None
    restricted_area_id: Optional[uuid.UUID] = None


@router.get("")
async def list_departments(
    current: dict = Depends(require_roles(UserRole.super_admin, UserRole.admin)),
    _m:      dict = Depends(require_modules("departments")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    rows = await conn.fetch(
        """
        SELECT d.id, d.name, d.description, d.is_restricted,
               d.restricted_area_id, d.created_at,
               ra.name AS restricted_area_name,
               COUNT(su.id) AS member_count
        FROM departments d
        LEFT JOIN restricted_areas ra ON ra.id = d.restricted_area_id
        LEFT JOIN staff_users su ON su.department_id = d.id AND su.is_active
        GROUP BY d.id, ra.name
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

    row = await conn.fetchrow(
        """
        INSERT INTO departments (name, description, is_restricted, restricted_area_id)
        VALUES ($1, $2, $3, $4)
        RETURNING id, name, description, is_restricted, restricted_area_id, created_at
        """,
        body.name, body.description, body.is_restricted, body.restricted_area_id,
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
    existing = await conn.fetchrow("SELECT id FROM departments WHERE id=$1", department_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Department not found")

    if body.name:
        name_taken = await conn.fetchval("SELECT 1 FROM departments WHERE name=$1 AND id!=$2", body.name, department_id)
        if name_taken:
            raise HTTPException(status.HTTP_409_CONFLICT, detail="A department with this name already exists")

    row = await conn.fetchrow(
        """
        UPDATE departments SET
            name              = COALESCE($2, name),
            description       = COALESCE($3, description),
            is_restricted     = COALESCE($4, is_restricted),
            restricted_area_id = CASE WHEN $5::bool THEN $6 ELSE COALESCE($5, is_restricted) END
        WHERE id = $1
        RETURNING id, name, description, is_restricted, restricted_area_id, created_at
        """,
        department_id,
        body.name,
        body.description,
        body.is_restricted,
        body.is_restricted,
        body.restricted_area_id,
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
