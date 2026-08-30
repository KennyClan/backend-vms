import uuid
import json
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from database import get_conn
from utils.auth import require_roles, require_modules
from models import UserRole
import asyncpg

router = APIRouter(prefix="/floor-plan", tags=["Floor Plan"])


# ── Pydantic Models ──────────────────────────────────────────────

class FloorCreateIn(BaseModel):
    name: str
    floor_number: int

class FloorUpdateIn(BaseModel):
    name: str | None = None
    floor_number: int | None = None

class ObjectCreateIn(BaseModel):
    object_type: str
    x: float = 0
    y: float = 0
    width: float = 200
    height: float = 150
    rotation: float = 0
    name: str = ""
    properties: dict = {}
    z_index: int = 0

class ObjectUpdateIn(BaseModel):
    x: float | None = None
    y: float | None = None
    width: float | None = None
    height: float | None = None
    rotation: float | None = None
    name: str | None = None
    properties: dict | None = None
    z_index: int | None = None
    floor_id: uuid.UUID | None = None

class BulkSaveIn(BaseModel):
    objects: list[ObjectCreateIn]


# Map the floor-plan editor's access_level vocabulary onto the room-level
# restriction enum (none | restricted | highly_restricted) enforced by the
# Room Guard and capacity flows.
_ACCESS_TO_RESTRICTION = {
    "Restricted": "restricted",
    "Highly Restricted": "highly_restricted",
    "Public": "none",
    "Employee Only": "none",
}


async def _sync_post_level(conn: asyncpg.Connection, properties):
    """When a room object is linked to a VMS post, mirror its access_level
    onto posts.restriction_level so Room Guard enforcement and capacity
    checks see the same level the editor shows."""
    if not isinstance(properties, dict):
        return
    post_id = properties.get("post_id")
    if not post_id:
        return
    level = _ACCESS_TO_RESTRICTION.get(properties.get("access_level"), "none")
    await conn.execute(
        "UPDATE posts SET restriction_level=$1 WHERE id=$2",
        level, post_id,
    )


def _row_to_dict(row):
    d = dict(row)
    if "properties" in d and isinstance(d["properties"], str):
        try:
            d["properties"] = json.loads(d["properties"])
        except Exception:
            d["properties"] = {}
    if "properties" in d and d["properties"] is None:
        d["properties"] = {}
    return d


# ── Floor Endpoints ──────────────────────────────────────────────

@router.get("")
async def list_floors(
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin, UserRole.guard, UserRole.recep)),
    _m:      dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    rows = await conn.fetch("SELECT * FROM floors ORDER BY floor_number ASC")
    return [dict(r) for r in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_floor(
    body: FloorCreateIn,
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchval(
        "SELECT 1 FROM floors WHERE floor_number=$1", body.floor_number
    )
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"Floor {body.floor_number} already exists")
    row = await conn.fetchrow(
        "INSERT INTO floors (name, floor_number) VALUES ($1, $2) RETURNING *",
        body.name, body.floor_number,
    )
    return dict(row)


@router.patch("/{floor_id}")
async def update_floor(
    floor_id: uuid.UUID,
    body: FloorUpdateIn,
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchrow("SELECT id FROM floors WHERE id=$1", floor_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Floor not found")
    if body.floor_number is not None:
        dup = await conn.fetchval(
            "SELECT 1 FROM floors WHERE floor_number=$1 AND id!=$2", body.floor_number, floor_id
        )
        if dup:
            raise HTTPException(status.HTTP_409_CONFLICT, detail=f"Floor number {body.floor_number} already exists")
    row = await conn.fetchrow(
        """UPDATE floors SET
            name = COALESCE($2, name),
            floor_number = COALESCE($3, floor_number)
        WHERE id=$1 RETURNING *""",
        floor_id, body.name, body.floor_number,
    )
    return dict(row)


@router.delete("/{floor_id}")
async def delete_floor(
    floor_id: uuid.UUID,
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchrow("SELECT id FROM floors WHERE id=$1", floor_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Floor not found")
    await conn.execute("DELETE FROM floor_plan_objects WHERE floor_id=$1", floor_id)
    await conn.execute("DELETE FROM floors WHERE id=$1", floor_id)
    return {"ok": True}


# ── Object Endpoints ─────────────────────────────────────────────

@router.get("/{floor_id}/objects")
async def list_objects(
    floor_id: uuid.UUID,
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin, UserRole.guard, UserRole.recep)),
    _m:      dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    rows = await conn.fetch(
        "SELECT * FROM floor_plan_objects WHERE floor_id=$1 ORDER BY z_index ASC, created_at ASC",
        floor_id,
    )
    return [_row_to_dict(r) for r in rows]


@router.post("/{floor_id}/objects", status_code=status.HTTP_201_CREATED)
async def create_object(
    floor_id: uuid.UUID,
    body: ObjectCreateIn,
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    floor_exists = await conn.fetchval("SELECT 1 FROM floors WHERE id=$1", floor_id)
    if not floor_exists:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Floor not found")
    row = await conn.fetchrow(
        """INSERT INTO floor_plan_objects
            (floor_id, object_type, x, y, width, height, rotation, name, properties, z_index)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        RETURNING *""",
        floor_id, body.object_type, body.x, body.y, body.width, body.height,
        body.rotation, body.name, json.dumps(body.properties), body.z_index,
    )
    if body.object_type == "room":
        await _sync_post_level(conn, body.properties)
    return _row_to_dict(row)


@router.patch("/objects/{object_id}")
async def update_object(
    object_id: uuid.UUID,
    body: ObjectUpdateIn,
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchrow("SELECT id FROM floor_plan_objects WHERE id=$1", object_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Object not found")
    props_json = json.dumps(body.properties) if body.properties is not None else None
    row = await conn.fetchrow(
        """UPDATE floor_plan_objects SET
            x = COALESCE($2, x),
            y = COALESCE($3, y),
            width = COALESCE($4, width),
            height = COALESCE($5, height),
            rotation = COALESCE($6, rotation),
            name = COALESCE($7, name),
            properties = COALESCE($8, properties),
            z_index = COALESCE($9, z_index),
            floor_id = COALESCE($10, floor_id)
        WHERE id=$1 RETURNING *""",
        object_id,
        body.x, body.y, body.width, body.height,
        body.rotation, body.name, props_json, body.z_index, body.floor_id,
    )
    if body.properties is not None:
        await _sync_post_level(conn, body.properties)
    return _row_to_dict(row)


@router.delete("/objects/{object_id}")
async def delete_object(
    object_id: uuid.UUID,
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchrow("SELECT id FROM floor_plan_objects WHERE id=$1", object_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Object not found")
    await conn.execute("DELETE FROM floor_plan_objects WHERE id=$1", object_id)
    return {"ok": True}


@router.post("/objects/{object_id}/duplicate")
async def duplicate_object(
    object_id: uuid.UUID,
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    existing = await conn.fetchrow("SELECT * FROM floor_plan_objects WHERE id=$1", object_id)
    if not existing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Object not found")
    e = dict(existing)
    row = await conn.fetchrow(
        """INSERT INTO floor_plan_objects
            (floor_id, object_type, x, y, width, height, rotation, name, properties, z_index)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        RETURNING *""",
        e["floor_id"], e["object_type"], e["x"] + 30, e["y"] + 30,
        e["width"], e["height"], e["rotation"],
        e["name"] + " (copy)", e["properties"], e["z_index"],
    )
    return _row_to_dict(row)


@router.post("/{floor_id}/objects/bulk")
async def bulk_save_objects(
    floor_id: uuid.UUID,
    body: BulkSaveIn,
    current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin)),
    _m:      dict = Depends(require_modules("floorplan")),
    conn: asyncpg.Connection = Depends(get_conn),
):
    floor_exists = await conn.fetchval("SELECT 1 FROM floors WHERE id=$1", floor_id)
    if not floor_exists:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Floor not found")
    async with conn.transaction():
        await conn.execute("DELETE FROM floor_plan_objects WHERE floor_id=$1", floor_id)
        for obj in body.objects:
            await conn.execute(
                """INSERT INTO floor_plan_objects
                    (floor_id, object_type, x, y, width, height, rotation, name, properties, z_index)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)""",
                floor_id, obj.object_type, obj.x, obj.y, obj.width, obj.height,
                obj.rotation, obj.name, json.dumps(obj.properties), obj.z_index,
            )
            if obj.object_type == "room":
                await _sync_post_level(conn, obj.properties)
    return {"ok": True, "count": len(body.objects)}
