import uuid
from datetime import date
from typing import Optional
import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request
from database import get_conn
from schemas import VisitRequestIn, VisitRequestOut, CheckInIn, ApprovalIn
from models import UserRole, ApprovalStatus
from utils.auth import get_current_user, require_roles
from utils.audit import write_audit
from services.email import send_qr_pass_email, send_status_update_email
from limiter import limiter
import asyncio

router = APIRouter(prefix="/visit-requests", tags=["Visit Requests"])


@router.get("", response_model=list[VisitRequestOut])
async def list_requests(
    approval_status: Optional[str]  = None,
    visit_status:    Optional[str]  = None,
    visit_date:      Optional[date] = None,
    _:               dict           = Depends(get_current_user),
    conn: asyncpg.Connection        = Depends(get_conn),
):
    clauses, args = [], []
    if approval_status:
        args.append(approval_status); clauses.append(f"approval_status = ${len(args)}")
    if visit_status:
        args.append(visit_status); clauses.append(f"status = ${len(args)}")
    if visit_date:
        args.append(visit_date); clauses.append(f"visit_date = ${len(args)}")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows  = await conn.fetch(f"SELECT * FROM visit_requests {where} ORDER BY created_at DESC", *args)
    return [dict(r) for r in rows]


@router.post("", response_model=VisitRequestOut, status_code=201)
async def create_request(
    body: VisitRequestIn,
    conn: asyncpg.Connection = Depends(get_conn),
):
    visitor_id = body.visitor_id

    # If ID details were supplied and no explicit visitor_id was given,
    # upsert a matching Visitors record so this person shows up in the
    # Visitors directory too (matched by id_type + id_number).
    if visitor_id is None and body.id_type and body.id_number:
        visitor_row = await conn.fetchrow(
            """
            INSERT INTO visitors (full_name, company, phone, email, id_type, id_number)
            VALUES ($1,$2,$3,$4,$5,$6)
            ON CONFLICT (id_type, id_number) DO UPDATE SET
              full_name  = EXCLUDED.full_name,
              company    = COALESCE(EXCLUDED.company, visitors.company),
              phone      = COALESCE(EXCLUDED.phone, visitors.phone),
              email      = COALESCE(EXCLUDED.email, visitors.email),
              updated_at = NOW()
            RETURNING id
            """,
            body.visitor_name, body.company, body.phone, body.visitor_email,
            body.id_type, body.id_number,
        )
        visitor_id = visitor_row["id"]

    # Block a new submission while this person already has an unresolved
    # (Pending) request — match by visitor_id OR by email, whichever matches.
    pending = await conn.fetchrow(
        """
        SELECT id FROM visit_requests
        WHERE approval_status='Pending'
          AND (
            ($1::uuid IS NOT NULL AND visitor_id = $1)
            OR ($2::citext IS NOT NULL AND visitor_email = $2)
          )
        LIMIT 1
        """,
        visitor_id, body.visitor_email,
    )

    if pending:
        raise HTTPException(
            409,
            "You already have a visit request awaiting approval. "
            "Please wait for it to be approved or rejected before submitting a new one.",
        )

    row = await conn.fetchrow(
        """
        INSERT INTO visit_requests
          (visitor_id, visitor_name, visitor_email, host_name, host_staff_id,
           visit_date, expected_time, purpose)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *
        """,
        visitor_id, body.visitor_name, body.visitor_email,
        body.host_name, body.host_staff_id,
        body.visit_date, body.expected_time, body.purpose,
    )
    await write_audit(conn, "Request Created", visit_request_id=row["id"],
                      visitor_name=row["visitor_name"], detail=f"Visit date: {row['visit_date']}")
    return dict(row)


@router.patch("/{request_id}/approve")
async def approve_or_reject(
    request_id: uuid.UUID,
    body:       ApprovalIn,
    current:    dict               = Depends(require_roles(UserRole.admin, UserRole.recep)),
    conn:       asyncpg.Connection = Depends(get_conn),
):
    row = await conn.fetchrow("SELECT visitor_name FROM visit_requests WHERE id=$1", request_id)
    if not row:
        raise HTTPException(404, "Request not found")
    if body.action == ApprovalStatus.approved:
        await conn.execute(
            "UPDATE visit_requests SET approval_status='Approved', status='Pending Arrival', approved_by=$1, approved_at=NOW(), destination_post_id=$3 WHERE id=$2",
            uuid.UUID(str(current["id"])), request_id, body.destination_post_id,
        )
        event = "Request Approved"

        # Fetch full request to send email
        full = await conn.fetchrow("SELECT * FROM visit_requests WHERE id=$1", request_id)
        if full and full["visitor_email"]:
            asyncio.create_task(send_qr_pass_email(
                to_email     = full["visitor_email"],
                visitor_name = full["visitor_name"],
                host_name    = full["host_name"],
                visit_date   = str(full["visit_date"]),
                expected_time= str(full["expected_time"]) if full["expected_time"] else "",
                purpose      = full["purpose"],
                qr_ref       = full["qr_ref"],
            ))
    else:
        await conn.execute(
            "UPDATE visit_requests SET approval_status='Rejected', status='Rejected', approved_by=$1, approved_at=NOW(), rejection_reason=$2 WHERE id=$3",
            uuid.UUID(str(current["id"])), body.rejection_reason, request_id,
        )
        event = "Request Rejected"

        full = await conn.fetchrow("SELECT * FROM visit_requests WHERE id=$1", request_id)
        if full and full["visitor_email"]:
            note = f"Reason: {body.rejection_reason}" if body.rejection_reason else ""
            asyncio.create_task(send_status_update_email(
                to_email     = full["visitor_email"],
                visitor_name = full["visitor_name"],
                host_name    = full["host_name"],
                visit_date   = str(full["visit_date"]),
                status       = "Rejected",
                extra_note   = note,
            ))
    await write_audit(conn, event, actor=current, visit_request_id=request_id, visitor_name=row["visitor_name"])
    return {"id": request_id, "approval_status": body.action.value}


@router.patch("/{request_id}/check-in")
async def check_in(
    request_id: uuid.UUID,
    body:       CheckInIn,
    current:    dict               = Depends(require_roles(UserRole.admin, UserRole.guard)),
    conn:       asyncpg.Connection = Depends(get_conn),
):
    row = await conn.fetchrow(
        "SELECT visitor_name, visitor_email, host_name, visit_date, approval_status FROM visit_requests WHERE id=$1", request_id
    )
    if not row:
        raise HTTPException(404, "Request not found")
    if row["approval_status"] != "Approved":
        raise HTTPException(400, "Request must be Approved before check-in")
    await conn.execute(
        "UPDATE visit_requests SET status='Checked In', badge_number=$1, visitor_id_verified=$2, checked_in_at=NOW(), checked_in_by=$3 WHERE id=$4",
        body.badge_number, body.visitor_id_verified, uuid.UUID(str(current["id"])), request_id,
    )
    await write_audit(conn, "Checked In", actor=current, visit_request_id=request_id,
                      visitor_name=row["visitor_name"], detail=f"Badge: {body.badge_number}")
    if row["visitor_email"]:
        asyncio.create_task(send_status_update_email(
            to_email     = row["visitor_email"],
            visitor_name = row["visitor_name"],
            host_name    = row["host_name"],
            visit_date   = str(row["visit_date"]),
            status       = "Checked In",
        ))
    return {"id": request_id, "status": "Checked In", "badge_number": body.badge_number}


@router.patch("/{request_id}/check-out")
async def check_out(
    request_id: uuid.UUID,
    current:    dict               = Depends(require_roles(UserRole.admin, UserRole.guard)),
    conn:       asyncpg.Connection = Depends(get_conn),
):
    row = await conn.fetchrow(
        "SELECT visitor_name, visitor_email, host_name, visit_date, status FROM visit_requests WHERE id=$1", request_id
    )
    if not row:
        raise HTTPException(404, "Request not found")
    if row["status"] != "Checked In":
        raise HTTPException(400, "Visitor must be Checked In before check-out")
    await conn.execute(
        "UPDATE visit_requests SET status='Checked Out', checked_out_at=NOW(), checked_out_by=$1 WHERE id=$2",
        uuid.UUID(str(current["id"])), request_id,
    )
    await write_audit(conn, "Checked Out", actor=current, visit_request_id=request_id,
                      visitor_name=row["visitor_name"])
    if row["visitor_email"]:
        asyncio.create_task(send_status_update_email(
            to_email     = row["visitor_email"],
            visitor_name = row["visitor_name"],
            host_name    = row["host_name"],
            visit_date   = str(row["visit_date"]),
            status       = "Checked Out",
        ))
    return {"id": request_id, "status": "Checked Out"}


@router.get("/{request_id}/restricted-access")
async def get_restricted_access(
    request_id: uuid.UUID,
    current:    dict               = Depends(get_current_user),
    conn:       asyncpg.Connection = Depends(get_conn),
):
    """Check if a visit request has pre-approved restricted area access."""
    req = await conn.fetchrow("SELECT id FROM visit_requests WHERE id=$1", request_id)
    if not req:
        raise HTTPException(404, "Request not found")

    row = await conn.fetchrow(
        """
        SELECT rac.*, ra.name AS area_name, ra.floor
        FROM restricted_access rac
        JOIN restricted_areas ra ON ra.id = rac.restricted_area_id
        WHERE rac.visit_request_id = $1
        ORDER BY rac.created_at DESC
        LIMIT 1
        """,
        request_id,
    )
    if not row:
        return {"has_restricted_access": False}

    return {
        "has_restricted_access": True,
        "restricted_area_id": row["restricted_area_id"],
        "area_name": row["area_name"],
        "floor": row["floor"],
        "status": row["status"],
        "restricted_badge": row["restricted_badge"] or None,
    }


@router.get("/by-qr/{qr_ref}", response_model=VisitRequestOut)
@limiter.limit("10/minute")
async def lookup_by_qr(
    request: Request,
    qr_ref: str,
    conn:   asyncpg.Connection = Depends(get_conn),
):
    row = await conn.fetchrow("SELECT * FROM visit_requests WHERE qr_ref=$1", qr_ref)
    if not row:
        raise HTTPException(404, "QR code not found")
    return dict(row)


@router.get("/retrieve-pass")
@limiter.limit("5/minute")
async def retrieve_pass(
    request: Request,
    email: str,
    conn:  asyncpg.Connection = Depends(get_conn),
):
    """Visitor retrieves their QR pass by email — returns latest approved request."""
    rows = await conn.fetch(
        """
        SELECT * FROM visit_requests
        WHERE visitor_email = $1
          AND approval_status = 'Approved'
          AND status NOT IN ('Checked Out', 'Rejected')
        ORDER BY visit_date DESC
        LIMIT 5
        """,
        email.lower(),
    )
    if not rows:
        raise HTTPException(404, "No approved visit requests found for this email.")
    return [dict(r) for r in rows]


@router.post("/resend-pass/{request_id}")
@limiter.limit("3/minute")
async def resend_pass(
    request: Request,
    request_id: uuid.UUID,
    conn:       asyncpg.Connection = Depends(get_conn),
):
    """Resend QR pass email to visitor."""
    row = await conn.fetchrow("SELECT * FROM visit_requests WHERE id=$1", request_id)
    if not row:
        raise HTTPException(404, "Request not found")
    if not row["visitor_email"]:
        raise HTTPException(400, "No email address on file for this visitor")
    if row["approval_status"] != "Approved":
        raise HTTPException(400, "Request is not approved yet")

    sent = await send_qr_pass_email(
        to_email      = row["visitor_email"],
        visitor_name  = row["visitor_name"],
        host_name     = row["host_name"],
        visit_date    = str(row["visit_date"]),
        expected_time = str(row["expected_time"]) if row["expected_time"] else "",
        purpose       = row["purpose"],
        qr_ref        = row["qr_ref"],
    )
    if not sent:
        raise HTTPException(500, "Failed to send email. Check server logs.")
    return {"detail": "QR pass sent successfully", "to": row["visitor_email"]}
