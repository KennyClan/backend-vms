import uuid
from datetime import date
from typing import Optional
import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from database import get_conn
from schemas import VisitRequestIn, VisitRequestOut, CheckInIn, ApprovalIn, EmployeeVisitRequestIn
from models import UserRole, ApprovalStatus
from utils.auth import get_current_user, require_roles
from utils.audit import write_audit
from services.email import send_qr_pass_email, send_status_update_email, send_wayfinding_email
from limiter import limiter
import asyncio

router = APIRouter(prefix="/visit-requests", tags=["Visit Requests"])


@router.get("", response_model=list[VisitRequestOut])
async def list_requests(
    approval_status: Optional[str]  = None,
    visit_status:    Optional[str]  = None,
    visit_date:      Optional[date] = None,
    current:         dict           = Depends(get_current_user),
    conn: asyncpg.Connection        = Depends(get_conn),
):
    clauses, args = [], []
    if approval_status:
        args.append(approval_status); clauses.append(f"approval_status = ${len(args)}")
    if visit_status:
        args.append(visit_status); clauses.append(f"status = ${len(args)}")
    if visit_date:
        args.append(visit_date); clauses.append(f"visit_date = ${len(args)}")

    # Employees can only see requests where they are the host
    if current["role"] == UserRole.employee.value:
        args.append(uuid.UUID(str(current["id"]))); clauses.append(f"host_staff_id = ${len(args)}")

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

    # Spec routing: match the stated host name against employee records
    # (exact, case-insensitive). Match found -> route directly to that
    # employee's pending-approval queue by setting host_staff_id. No match ->
    # left unassigned so the receptionist can route it, or reject with reason.
    host_staff_id = body.host_staff_id
    host_name = (body.host_name or "").strip()
    candidate = None
    if host_staff_id is not None:
        candidate = await conn.fetchrow(
            "SELECT id, name FROM staff_users WHERE id=$1 AND role='Employee' AND is_active=true",
            host_staff_id,
        )
    if not candidate:
        candidate = await conn.fetchrow(
            """SELECT id, name FROM staff_users
               WHERE role='Employee' AND is_active=true
                 AND lower(trim(name)) = lower($1)
               LIMIT 1""",
            host_name,
        )
    host_staff_id = candidate["id"] if candidate else None
    if candidate:
        host_name = candidate["name"]

    # Auto-derive destination_type from host's department if host_staff_id provided
    destination_type = body.destination_type or "Normal"
    if host_staff_id:
        dept_info = await conn.fetchrow(
            """
            SELECT d.is_restricted
            FROM staff_users su
            JOIN departments d ON d.id = su.department_id
            WHERE su.id = $1
            """,
            host_staff_id,
        )
        if dept_info and dept_info["is_restricted"]:
            destination_type = "Restricted"

    row = await conn.fetchrow(
        """
        INSERT INTO visit_requests
          (visitor_id, visitor_name, visitor_email, host_name, host_staff_id,
           visit_date, expected_time, purpose, destination_type)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *
        """,
        visitor_id, body.visitor_name, body.visitor_email,
        host_name, host_staff_id,
        body.visit_date, body.expected_time, body.purpose, destination_type,
    )
    matched = "matched to employee" if host_staff_id else "no matching employee"
    await write_audit(conn, "Request Created", visit_request_id=row["id"],
                      visitor_name=row["visitor_name"], detail=f"Visit date: {row['visit_date']}, Destination: {destination_type}, Host: {matched}")
    return dict(row)


@router.patch("/{request_id}/approve")
async def approve_or_reject(
    request_id: uuid.UUID,
    body:       ApprovalIn,
    current:    dict               = Depends(get_current_user),
    conn:       asyncpg.Connection = Depends(get_conn),
):
    row = await conn.fetchrow("SELECT * FROM visit_requests WHERE id=$1", request_id)
    if not row:
        raise HTTPException(404, "Request not found")

    # Permission check: who may act on this request.
    #   * Employee  -> only their own requests (approve or reject).
    #   * Receptionist -> may ONLY reject (they route mis-assigned requests
    #     to the right employee via /assign; they never approve).
    #   * Admin / Super Admin -> NO approval or rejection; that stays with
    #     the host Employee and the Receptionist per the access spec.
    role = current["role"]
    if role == UserRole.employee.value:
        if row["host_staff_id"] != uuid.UUID(str(current["id"])):
            raise HTTPException(403, "You can only approve requests where you are the host")
    elif role == UserRole.recep.value:
        if body.action != ApprovalStatus.rejected:
            raise HTTPException(403, "Only the host employee can approve a request — receptionists route or reject")
    else:
        raise HTTPException(403, "Insufficient permissions")

    # Rejection requires a reason
    if body.action == ApprovalStatus.rejected and not body.rejection_reason:
        raise HTTPException(400, "Rejection reason is required")

    if body.action == ApprovalStatus.approved:
        # Room capacity check before finalizing approval into a room
        if body.destination_post_id:
            post = await conn.fetchrow(
                "SELECT capacity FROM posts WHERE id=$1", body.destination_post_id
            )
            if not post:
                raise HTTPException(404, "Destination room not found")
            occ = await conn.fetchval(
                """SELECT COUNT(*) FROM room_visits
                   WHERE post_id=$1 AND departed_at IS NULL""",
                body.destination_post_id,
            )
            if occ >= post["capacity"]:
                raise HTTPException(
                    409,
                    f"Destination room is at capacity ({occ}/{post['capacity']}) — choose another room",
                )
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


class AssignIn(BaseModel):
    host_staff_id: uuid.UUID


@router.post("/{request_id}/assign", response_model=VisitRequestOut)
async def assign_employee(
    request_id: uuid.UUID,
    body:       AssignIn,
    current:    dict               = Depends(require_roles(UserRole.recep, UserRole.admin, UserRole.super_admin)),
    conn:       asyncpg.Connection = Depends(get_conn),
):
    """Receptionist (or admin) routes a mis-assigned/unassigned request to
    the right employee. When a visitor or guard types the host name wrong
    the request has no host_staff_id — reception sees it unassigned, picks
    the correct employee here, and it lands back in that employee's pending
    queue for approval. Any previous approval/destination is reset since the
    new host still has to approve."""
    row = await conn.fetchrow("SELECT id, status, visitor_name FROM visit_requests WHERE id=$1", request_id)
    if not row:
        raise HTTPException(404, "Request not found")
    if row["status"] in ("Checked In", "Checked Out"):
        raise HTTPException(400, "This visit has already started — it can't be re-assigned")

    emp = await conn.fetchrow(
        "SELECT id, name, email, role, is_active FROM staff_users WHERE id=$1",
        body.host_staff_id,
    )
    if not emp:
        raise HTTPException(404, "Selected employee not found")
    if not emp["is_active"]:
        raise HTTPException(400, "Selected employee is not active")

    await conn.execute(
        """UPDATE visit_requests
           SET host_staff_id=$1, host_name=$2, approval_status='Pending', status='Pending',
               rejection_reason=NULL, approved_by=NULL, approved_at=NULL, destination_post_id=NULL
           WHERE id=$3""",
        emp["id"], emp["name"], request_id,
    )
    await write_audit(conn, "Request Assigned", actor=current, visit_request_id=request_id,
                      visitor_name=row["visitor_name"],
                      detail=f"Re-assigned to host {emp['name']} for approval")

    return dict(await conn.fetchrow("SELECT * FROM visit_requests WHERE id=$1", request_id))


@router.patch("/{request_id}/check-in")
async def check_in(
    request_id: uuid.UUID,
    body:       CheckInIn,
    current:    dict               = Depends(require_roles(UserRole.super_admin, UserRole.admin, UserRole.recep)),
    conn:       asyncpg.Connection = Depends(get_conn),
):
    """FRONT DESK (building entrance, not room-specific): scan the visitor's
    QR pass, verify ID, issue the physical badge (badge_number). Room Guards
    never issue badges — their scan is room-specific via /posts/{id}/arrivals."""
    row = await conn.fetchrow(
        "SELECT id, visitor_id, visitor_name, visitor_email, host_name, host_staff_id, visit_date, qr_ref, approval_status, destination_type, destination_post_id FROM visit_requests WHERE id=$1", request_id
    )
    if not row:
        raise HTTPException(404, "Request not found")
    if row["approval_status"] != "Approved":
        raise HTTPException(400, "Request must be Approved before check-in")
    # Physical badge lifecycle: issuing a badge registers a NEW badges row
    # (badge_number -> visitor_id + visit_request_id) so the full use history
    # is preserved. An active badge cannot be stolen by another visit; once
    # returned, the number can be issued again (a fresh row is appended).
    if body.badge_number:
        active = await conn.fetchrow(
            "SELECT visit_request_id FROM badges WHERE badge_number=$1 AND status='active'",
            body.badge_number,
        )
        if active and active["visit_request_id"] != request_id:
            raise HTTPException(409, f"Badge {body.badge_number} is already in use on another visit")
        await conn.execute(
            """INSERT INTO badges (badge_number, visitor_id, visit_request_id, issued_by, issued_at, status)
               VALUES ($1,$2,$3,$4,NOW(),'active')""",
            body.badge_number, row["visitor_id"], request_id, uuid.UUID(str(current["id"])),
        )
    await conn.execute(
        "UPDATE visit_requests SET status='Checked In', badge_number=$1, visitor_id_verified=$2, checked_in_at=NOW(), checked_in_by=$3 WHERE id=$4",
        body.badge_number, body.visitor_id_verified, uuid.UUID(str(current["id"])), request_id,
    )
    await write_audit(conn, "Checked In", actor=current, visit_request_id=request_id,
                      visitor_name=row["visitor_name"], detail=f"Badge: {body.badge_number}")

    # Auto-grant restricted-area access once a visitor destined for a
    # restricted department actually checks in, so the guard can immediately
    # issue a restricted badge at the Security Desk.
    dest = row["destination_type"]
    dept_area = None
    if row["host_staff_id"]:
        dept_info = await conn.fetchrow(
            """
            SELECT d.is_restricted, d.restricted_area_id
            FROM staff_users su
            JOIN departments d ON d.id = su.department_id
            WHERE su.id = $1
            """,
            row["host_staff_id"],
        )
        if dept_info and dept_info["is_restricted"]:
            if dest != "Restricted":
                dest = "Restricted"
                await conn.execute(
                    "UPDATE visit_requests SET destination_type='Restricted' WHERE id=$1",
                    request_id,
                )
            dept_area = dept_info["restricted_area_id"]
    if dest == "Restricted" and dept_area:
        existing = await conn.fetchval(
            "SELECT 1 FROM restricted_access WHERE visit_request_id=$1 AND restricted_area_id=$2",
            request_id, dept_area,
        )
        if not existing:
            await conn.execute(
                """INSERT INTO restricted_access (visit_request_id, restricted_area_id, status, approved_by, granted_at)
                   VALUES ($1, $2, 'Pending', $3, NOW())""",
                request_id, dept_area, uuid.UUID(str(current["id"])),
            )
            await write_audit(
                conn, "Restricted Access Auto-Granted", actor=current,
                visit_request_id=request_id, visitor_name=row["visitor_name"],
                detail="Auto-granted at check-in for restricted destination",
            )

    if row["visitor_email"]:
        destination = None
        if row["destination_post_id"]:
            destination = await conn.fetchrow(
                "SELECT name, floor FROM posts WHERE id=$1", row["destination_post_id"]
            )
        if destination and destination["name"]:
            asyncio.create_task(send_wayfinding_email(
                to_email          = row["visitor_email"],
                visitor_name      = row["visitor_name"],
                host_name         = row["host_name"],
                destination_name  = destination["name"],
                destination_floor = destination["floor"],
                qr_ref            = row["qr_ref"],
            ))
        else:
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
    current:    dict               = Depends(require_roles(UserRole.super_admin, UserRole.admin, UserRole.recep)),
    conn:       asyncpg.Connection = Depends(get_conn),
):
    """FRONT DESK building exit: marks the visit Checked Out and returns the
    badge. Room-specific departures are logged by the Room Guard via
    /posts/{id}/departures — the two flows never meet."""
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
    # Physical badge is returned at final checkout: status -> 'returned',
    # returned_at set, badge_number becomes available for reuse.
    await conn.execute(
        "UPDATE badges SET status='returned', returned_at=NOW() "
        "WHERE visit_request_id=$1 AND status='active'",
        request_id,
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
    """Check if a visit request has restricted area access — either a real
    grant row, or a recognised restricted destination (host in a restricted
    department) that hasn't been granted yet."""
    req = await conn.fetchrow(
        "SELECT id, destination_type, host_staff_id FROM visit_requests WHERE id=$1", request_id
    )
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
    if not row and req["destination_type"] == "Restricted" and req["host_staff_id"]:
        area = await conn.fetchrow(
            """
            SELECT ra.id, ra.name, ra.floor
            FROM staff_users su
            JOIN departments d ON d.id = su.department_id
            JOIN restricted_areas ra ON ra.id = d.restricted_area_id
            WHERE su.id = $1 AND d.is_restricted = TRUE AND ra.is_active = TRUE
            """,
            req["host_staff_id"],
        )
        if area:
            return {
                "has_restricted_access": True,
                "restricted_area_id": area["id"],
                "area_name": area["name"],
                "floor": area["floor"],
                "status": "Pending",
                "restricted_badge": None,
            }
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


# ---------------------------------------------------------------------
# Employee: self-initiated pre-approved visit
# ---------------------------------------------------------------------
@router.post("/self-visit", response_model=VisitRequestOut, status_code=201)
async def create_self_visit(
    body: EmployeeVisitRequestIn,
    current: dict = Depends(require_roles(UserRole.employee)),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Employee creates a visit request for themselves — auto-approved immediately."""
    host_id = uuid.UUID(str(current["id"]))
    host_name = current["name"]

    # Auto-derive destination_type from employee's department
    destination_type = "Normal"
    dept_info = await conn.fetchrow(
        """
        SELECT d.is_restricted
        FROM staff_users su
        JOIN departments d ON d.id = su.department_id
        WHERE su.id = $1
        """,
        host_id,
    )
    if dept_info and dept_info["is_restricted"]:
        destination_type = "Restricted"

    row = await conn.fetchrow(
        """
        INSERT INTO visit_requests
          (visitor_name, visitor_email, company, phone,
           host_name, host_staff_id, visit_date, expected_time, purpose,
           approval_status, status, approved_by, approved_at, destination_type)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'Approved','Pending Arrival',$10,NOW(),$11)
          RETURNING *
        """,
        body.visitor_name, body.visitor_email, body.company, body.phone,
        host_name, host_id, body.visit_date, body.expected_time, body.purpose,
        host_id, destination_type,
    )

    await write_audit(conn, "Self-Visit Created", actor=current, visit_request_id=row["id"],
                      visitor_name=row["visitor_name"], detail=f"Auto-approved, date: {row['visit_date']}")

    # Send QR pass email immediately
    if body.visitor_email:
        asyncio.create_task(send_qr_pass_email(
            to_email     = body.visitor_email,
            visitor_name = body.visitor_name,
            host_name    = host_name,
            visit_date   = str(body.visit_date),
            expected_time= str(body.expected_time) if body.expected_time else "",
            purpose      = body.purpose,
            qr_ref       = row["qr_ref"],
        ))

    return dict(row)


# ---------------------------------------------------------------------
# Guard: destination arrival confirmation (restricted areas)
# ---------------------------------------------------------------------
class DestinationArrivalIn(BaseModel):
    badge_number: str


@router.post("/{request_id}/destination-arrival")
async def confirm_destination_arrival(
    request_id: uuid.UUID,
    body: DestinationArrivalIn,
    current: dict = Depends(require_roles(UserRole.guard, UserRole.admin, UserRole.super_admin)),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Guard at a restricted area confirms the visitor has arrived at their destination."""
    row = await conn.fetchrow("SELECT * FROM visit_requests WHERE id=$1", request_id)
    if not row:
        raise HTTPException(404, "Request not found")
    if row["destination_type"] != "Restricted":
        raise HTTPException(400, "This request is not for a restricted destination")
    if row["status"] not in ("Checked In", "Pending Arrival"):
        raise HTTPException(400, f"Visitor must be checked in first (current status: {row['status']})")

    await conn.execute(
        "UPDATE visit_requests SET arrived_at=NOW() WHERE id=$1",
        request_id,
    )
    await write_audit(conn, "Destination Arrival", actor=current, visit_request_id=request_id,
                      visitor_name=row["visitor_name"], detail=f"Badge: {body.badge_number}")

    return {"id": request_id, "arrived_at": "now", "detail": "Destination arrival confirmed"}


# ---------------------------------------------------------------------
# Receptionist / Admin / Employee: notify host of visitor arrival
# ---------------------------------------------------------------------
@router.post("/{request_id}/notify-host")
async def notify_host(
    request_id: uuid.UUID,
    current: dict = Depends(require_roles(UserRole.recep, UserRole.admin, UserRole.super_admin, UserRole.employee)),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Send an email to the host saying their visitor is waiting at the front desk."""
    row = await conn.fetchrow("SELECT * FROM visit_requests WHERE id=$1", request_id)
    if not row:
        raise HTTPException(404, "Request not found")
    if not row["host_staff_id"]:
        raise HTTPException(400, "No host staff assigned to this request")

    host = await conn.fetchrow("SELECT email, name FROM staff_users WHERE id=$1", row["host_staff_id"])
    if not host or not host["email"]:
        raise HTTPException(400, "Host has no email address on file")

    # Reuse the status update email with a custom message
    asyncio.create_task(send_status_update_email(
        to_email     = host["email"],
        visitor_name = row["visitor_name"],
        host_name    = host["name"],
        visit_date   = str(row["visit_date"]),
        status       = "Visitor Waiting",
        extra_note   = f"{row['visitor_name']} is waiting at the front desk for you.",
    ))

    await write_audit(conn, "Host Notified", actor=current, visit_request_id=request_id,
                      visitor_name=row["visitor_name"], detail=f"Notified host: {host['name']}")
    return {"detail": f"Notification sent to {host['name']}"}


# ---------------------------------------------------------------------
# Room capacity monitoring (all rooms, not just restricted)
# ---------------------------------------------------------------------
@router.get("/room-capacity")
async def room_capacity(
    current: dict = Depends(require_roles(UserRole.recep, UserRole.admin, UserRole.super_admin)),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Current occupancy across all rooms/posts."""
    rows = await conn.fetch(
        """
        SELECT p.id, p.name, p.floor, p.capacity,
               COUNT(rv.id) FILTER (WHERE rv.departed_at IS NULL) AS current_occupancy
        FROM posts p
        LEFT JOIN room_visits rv ON rv.post_id = p.id
        GROUP BY p.id, p.name, p.floor
        ORDER BY p.floor, p.name
        """
    )
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------
# Employee list (for dropdown selection when creating visit requests)
# ---------------------------------------------------------------------
@router.get("/employees")
async def list_employees(
    current: dict = Depends(get_current_user),
    conn: asyncpg.Connection = Depends(get_conn),
):
    """Active employees that can be selected as hosts."""
    rows = await conn.fetch(
        """
        SELECT su.id, su.name, su.email, d.name AS department_name
        FROM staff_users su
        LEFT JOIN departments d ON d.id = su.department_id
        WHERE su.role = 'Employee' AND su.is_active = true
        ORDER BY su.name
        """
    )
    return [dict(r) for r in rows]
