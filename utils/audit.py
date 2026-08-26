import uuid
import logging
from typing import Optional
import asyncpg

logger = logging.getLogger(__name__)


async def write_audit(
    conn:             asyncpg.Connection,
    event_type:       str,
    actor:            Optional[dict]      = None,
    visit_request_id: Optional[uuid.UUID] = None,
    visitor_id:       Optional[uuid.UUID] = None,
    visitor_name:     Optional[str]       = None,
    detail:           Optional[str]       = None,
):
    """
    Write an audit log entry.

    This never raises. Audit logging is best-effort: if the DB connection
    is slow to respond (e.g. a paused/waking managed Postgres instance) or
    the insert otherwise fails, we log the error and move on rather than
    failing the caller's actual request (approve/reject/check-in/etc).
    """
    try:
        await conn.execute(
            """
            INSERT INTO audit_log
              (event_type, actor_staff_id, actor_name, visit_request_id, visitor_id, visitor_name, detail)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            """,
            event_type,
            uuid.UUID(str(actor["id"])) if actor else None,
            actor["name"] if actor else None,
            visit_request_id,
            visitor_id,
            visitor_name,
            detail,
        )
    except Exception as e:
        logger.warning(f"[write_audit] failed to record '{event_type}': {e}")
