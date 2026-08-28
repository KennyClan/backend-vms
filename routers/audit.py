import asyncpg
from fastapi import APIRouter, Depends
from database import get_conn
from models import UserRole
from utils.auth import require_roles, require_modules

router = APIRouter(prefix="/audit-log", tags=["Audit"])


@router.get("")
async def get_audit_log(
    limit:  int  = 100,
    offset: int  = 0,
    _:      dict = Depends(require_roles(UserRole.admin, UserRole.super_admin, UserRole.recep)),
    __:     dict = Depends(require_modules("audit")),
    conn:   asyncpg.Connection = Depends(get_conn),
):
    rows = await conn.fetch(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        limit, offset,
    )
    return [dict(r) for r in rows]
