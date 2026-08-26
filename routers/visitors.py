import uuid
from typing import Optional
import asyncpg
from fastapi import APIRouter, Depends, HTTPException
from database import get_conn
from schemas import VisitorIn, VisitorOut
from models import UserRole
from utils.auth import get_current_user, require_roles
from utils.audit import write_audit

router = APIRouter(prefix="/visitors", tags=["Visitors"])


@router.get("", response_model=list[VisitorOut])
async def list_visitors(
    q:      Optional[str]      = None,
    status: Optional[str]      = None,
    _:      dict               = Depends(get_current_user),
    conn:   asyncpg.Connection = Depends(get_conn),
):
    clauses, args = [], []
    if q:
        args.append(f"%{q}%")
        clauses.append(f"(full_name ILIKE ${len(args)} OR company ILIKE ${len(args)})")
    if status:
        args.append(status)
        clauses.append(f"status = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows  = await conn.fetch(f"SELECT * FROM visitors {where} ORDER BY created_at DESC", *args)
    return [dict(r) for r in rows]


@router.post("", response_model=VisitorOut, status_code=201)
async def create_visitor(
    body:    VisitorIn,
    current: dict               = Depends(require_roles(UserRole.admin, UserRole.recep)),
    conn:    asyncpg.Connection = Depends(get_conn),
):
    row = await conn.fetchrow(
        "INSERT INTO visitors (full_name, company, phone, email, id_type, id_number) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
        body.full_name, body.company, body.phone, body.email, body.id_type, body.id_number,
    )
    return dict(row)


@router.patch("/{visitor_id}/block")
async def toggle_block(
    visitor_id: uuid.UUID,
    current:    dict               = Depends(require_roles(UserRole.admin)),
    conn:       asyncpg.Connection = Depends(get_conn),
):
    row = await conn.fetchrow("SELECT status, full_name FROM visitors WHERE id=$1", visitor_id)
    if not row:
        raise HTTPException(404, "Visitor not found")
    new_status = "Blocked" if row["status"] == "Active" else "Active"
    event      = "Visitor Blocked" if new_status == "Blocked" else "Visitor Unblocked"
    await conn.execute("UPDATE visitors SET status=$1 WHERE id=$2", new_status, visitor_id)
    await write_audit(conn, event, actor=current, visitor_id=visitor_id, visitor_name=row["full_name"])
    return {"id": visitor_id, "status": new_status}
