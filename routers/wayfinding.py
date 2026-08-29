"""
Wayfinding — public, no-login endpoint that powers the visitor's
directions page after check-in.

The visitor opens the /wayfind/{qr_ref} link from their email. It renders
the destination floor with all rooms blank except the room they're heading
to (no GPS, no live tracking). The payload stops being served — and the
page shows a locked screen — once the guard at the destination scans the
badge and confirms arrival (room_visits at the destination post, or
visit_requests.arrived_at for restricted destinations), AND after the
visitor checks out.
"""

import json
import uuid

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request

from database import get_conn
from limiter import limiter

router = APIRouter(prefix="/wayfinding", tags=["Wayfinding"])


def _clean_object(row) -> dict | None:
    d = dict(row)
    props = d.get("properties")
    if isinstance(props, str):
        try:
            props = json.loads(props)
        except Exception:
            props = {}
    d["properties"] = props if isinstance(props, dict) else {}
    for k in ("id", "floor_id"):
        if k in d and d[k] is not None:
            d[k] = str(d[k])
    return d


@router.get("/{qr_ref}")
@limiter.limit("30/minute")
async def get_wayfinding(
    request: Request,
    qr_ref: str,
    conn: asyncpg.Connection = Depends(get_conn),
):
    row = await conn.fetchrow(
        """
        SELECT id, visitor_name, host_name, visit_date, status, approval_status,
               destination_post_id, destination_type, arrived_at
        FROM visit_requests
        WHERE qr_ref = $1
        """,
        qr_ref,
    )
    if not row:
        raise HTTPException(404, "Direction link not found")

    base = {
        "qr_ref": qr_ref,
        "visitor_name": row["visitor_name"],
        "host_name": row["host_name"],
        "visit_date": str(row["visit_date"]),
        "destination_name": None,
        "destination_floor": None,
        "destination_type": row["destination_type"],
    }

    dest_post = None
    if row["destination_post_id"]:
        dest_post = await conn.fetchrow(
            "SELECT id, name, floor FROM posts WHERE id = $1",
            row["destination_post_id"],
        )
    if dest_post:
        base["destination_name"] = dest_post["name"]
        base["destination_floor"] = dest_post["floor"]

    # --- Expiry ---------------------------------------------------------
    expired = False
    reason = None
    if row["approval_status"] != "Approved":
        expired, reason = True, "This visit was not approved."
    elif row["status"] == "Checked Out":
        expired, reason = True, "This visit is already complete — you have checked out."
    elif row["arrived_at"] is not None:
        expired, reason = True, "You've arrived at your destination."
    elif dest_post:
        arrived = await conn.fetchval(
            """
            SELECT 1 FROM room_visits rv
            JOIN visit_requests vr ON vr.id = rv.visit_request_id
            WHERE vr.qr_ref = $1 AND rv.post_id = $2 AND rv.departed_at IS NULL
            LIMIT 1
            """,
            qr_ref,
            dest_post["id"],
        )
        if arrived:
            expired, reason = True, "You've arrived at your destination."

    if expired:
        return {
            **base,
            "expired": True,
            "expired_reason": reason,
            "directions": [],
            "floor": None,
            "objects": [],
            "highlight_object_id": None,
        }

    # --- Map payload -----------------------------------------------------
    floor = None
    objects = []
    highlight_object_id = None
    if dest_post:
        floor = await conn.fetchrow(
            "SELECT id, name, floor_number FROM floors WHERE floor_number = $1",
            dest_post["floor"],
        )
        if floor:
            rows = await conn.fetch(
                "SELECT * FROM floor_plan_objects WHERE floor_id = $1 ORDER BY z_index ASC, created_at ASC",
                floor["id"],
            )
            objects = [_clean_object(r) for r in rows]

            target = dest_post["name"].strip().lower()
            for o in objects:
                if o["name"].strip().lower() == target:
                    highlight_object_id = o["id"]
                    break
            if not highlight_object_id:
                for o in objects:
                    if o["name"].strip().lower() and target in o["name"].strip().lower():
                        highlight_object_id = o["id"]
                        break

    directions = []
    if dest_post:
        if dest_post["floor"] > 1:
            directions.append(f"Head to Floor {dest_post['floor']} — take the elevator or stairs.")
        else:
            directions.append("Stay on the ground floor.")
        directions.append(f"Follow the floor signs to {dest_post['name']}.")

    return {
        **base,
        "expired": False,
        "expired_reason": None,
        "directions": directions,
        "floor": dict(floor) if floor else None,
        "objects": objects,
        "highlight_object_id": highlight_object_id,
    }