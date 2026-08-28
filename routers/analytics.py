import asyncpg
from fastapi import APIRouter, Depends
from database import get_conn
from models import UserRole
from utils.auth import require_roles, require_modules

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/summary")
async def analytics_summary(
    _:    dict               = Depends(require_roles(UserRole.admin, UserRole.recep, UserRole.super_admin)),
    __:   dict               = Depends(require_modules("analytics")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    summary = await conn.fetchrow(
        """
        SELECT
          COUNT(*)                                                    AS total_requests,
          COUNT(*) FILTER (WHERE approval_status = 'Pending')        AS pending,
          COUNT(*) FILTER (WHERE approval_status = 'Approved')       AS approved,
          COUNT(*) FILTER (WHERE approval_status = 'Rejected')       AS rejected,
          COUNT(*) FILTER (WHERE status          = 'Checked In')     AS currently_inside
        FROM visit_requests
        """
    )
    total_visitors = await conn.fetchval("SELECT COUNT(*) FROM visitors")
    weekly = await conn.fetch(
        """
        SELECT TO_CHAR(visit_date,'Dy') AS day, COUNT(*) AS visits
        FROM   visit_requests
        WHERE  visit_date >= CURRENT_DATE - INTERVAL '7 days'
        GROUP  BY visit_date, day
        ORDER  BY visit_date
        """
    )
    return {
        **dict(summary),
        "total_visitors": total_visitors,
        "weekly_traffic": [dict(r) for r in weekly],
    }
