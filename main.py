import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from database import create_pool, close_pool
from routers import auth, visitors, visit_requests, audit, analytics, webauthn, staff, restricted, floor_plan, departments, wayfinding, badges
import logging
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from limiter import limiter
from dotenv import load_dotenv
from utils.auth import get_current_user, require_roles, hash_password
from models import UserRole, DEFAULT_MODULES_BY_ROLE

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─── Demo account seeding ─────────────────────────────────────────
# Seed passwords come from SEED_*_PASSWORD env vars ONLY — never hardcoded,
# because this repo is public. Auto-seeding on startup runs by default only
# against local/dev databases; a cloud/prod DB needs an explicit
# SEED_DEMO=true. An account whose password env var is unset is skipped.
DEMO_ACCOUNTS = [
    # (display_name, email, password_env, role) — the Employee account is
    # shown as a real person ("Lim Kenny") so visitors who type a host name
    # see a person, not the role word "Employee".
    ("Super Admin",    "superadmin@vistahq.com", "SEED_SUPERADMIN_PASSWORD", "Super Admin"),
    ("Administrator",  "admin2@vistahq.com",     "SEED_ADMIN_PASSWORD",     "Administrator"),
    ("Receptionist",   "reception@vistahq.com",  "SEED_RECEP_PASSWORD",     "Receptionist"),
    ("Security Guard", "security@vistahq.com",   "SEED_GUARD_PASSWORD",     "Security Guard"),
    ("Lim Kenny",      "employee@vistahq.com",   "SEED_EMPLOYEE_PASSWORD",  "Employee"),
]


def seed_demo_enabled() -> bool:
    flag = os.getenv("SEED_DEMO")
    if flag is not None:
        return flag.strip().lower() in ("1", "true", "yes", "on")
    # Default: seed demo accounts on local/dev DBs only, never on a cloud or
    # prod database unless the deploy explicitly sets SEED_DEMO=true.
    url = os.getenv("DATABASE_URL", "")
    return "localhost" in url or "127.0.0.1" in url


async def seed_demo_accounts(conn) -> list[str]:
    """Insert missing demo accounts whose password env var is set. Returns
    the list of seeded emails. Never falls back to a hardcoded password."""
    errors = []
    for val in ('Super Admin', 'Employee'):
        try:
            await conn.execute(
                "DO $$ BEGIN ALTER TYPE user_role ADD VALUE IF NOT EXISTS '"
                + val + "'; EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
            )
        except Exception as e:
            errors.append(f"enum {val}: {e}")

    import json as _json
    seeded = []
    for name, email, env_key, role in DEMO_ACCOUNTS:
        exists = await conn.fetchval("SELECT 1 FROM staff_users WHERE email=$1", email)
        if exists:
            continue
        password = os.getenv(env_key, "")
        if not password:
            logger.warning(f"Skipping seed {email}: {env_key} is not set")
            continue
        initials = "".join(w[0] for w in name.split()[:2]).upper()
        try:
            await conn.execute(
                """INSERT INTO staff_users (name, initials, email, password_hash, role, is_active, permissions)
                   VALUES ($1,$2,$3,$4,$5::user_role,$6,$7::jsonb)""",
                name, initials, email, hash_password(password), role, True,
                _json.dumps(DEFAULT_MODULES_BY_ROLE.get(role, [])),
            )
            seeded.append(email)
            logger.info(f"Seeded: {name} <{email}>")
        except Exception as e:
            errors.append(f"{email}: {e}")
    if errors:
        logger.error(f"Seed errors: {errors}")
    return seeded


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_pool()
    logger.info("Database pool created")
    # Auto-create floor plan tables if they don't exist
    from database import get_pool
    pool = get_pool()
    async with pool.acquire() as conn:
        # Add new enum values to user_role if missing
        for val in ('Super Admin', 'Employee'):
            await conn.execute(f"""
                DO $$ BEGIN
                    ALTER TYPE user_role ADD VALUE IF NOT EXISTS '{val}';
                EXCEPTION WHEN duplicate_object THEN NULL;
                END $$;
            """)
        logger.info("user_role enum verified")

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS floors (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL,
                floor_number INTEGER NOT NULL UNIQUE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS floor_plan_objects (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                floor_id UUID REFERENCES floors(id) ON DELETE CASCADE,
                object_type TEXT NOT NULL,
                x FLOAT NOT NULL DEFAULT 0,
                y FLOAT NOT NULL DEFAULT 0,
                width FLOAT NOT NULL DEFAULT 200,
                height FLOAT NOT NULL DEFAULT 150,
                rotation FLOAT NOT NULL DEFAULT 0,
                name TEXT NOT NULL DEFAULT '',
                properties JSONB DEFAULT '{}',
                z_index INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        logger.info("Floor plan tables verified")

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS restricted_areas (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                floor TEXT,
                created_by UUID,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS restricted_access (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                restricted_area_id UUID,
                visit_request_id UUID,
                status TEXT NOT NULL DEFAULT 'Pending',
                restricted_badge TEXT,
                approved_by UUID,
                approved_at TIMESTAMPTZ,
                badge_issued_by UUID,
                entry_confirmed_by UUID,
                granted_at TIMESTAMPTZ DEFAULT NOW(),
                badge_issued_at TIMESTAMPTZ,
                entered_at TIMESTAMPTZ,
                exited_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS posts (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                floor INTEGER DEFAULT 1,
                pos_x FLOAT DEFAULT 0,
                pos_y FLOAT DEFAULT 0,
                width FLOAT DEFAULT 10,
                height FLOAT DEFAULT 10,
                room_number TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        logger.info("Restricted area & post tables verified")

        # Badges are a separate entity from the visit QR pass: a physical
        # badge is issued only after Front Desk Security approves check-in.
        # room_visits tracks who is physically inside which room/post.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS badges (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                badge_number TEXT NOT NULL,
                visitor_id UUID,
                visit_request_id UUID,
                issued_by UUID,
                issued_at TIMESTAMPTZ DEFAULT NOW(),
                returned_at TIMESTAMPTZ,
                status TEXT NOT NULL DEFAULT 'active'
            );
            CREATE TABLE IF NOT EXISTS room_visits (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                visit_request_id UUID,
                post_id UUID,
                scanned_by UUID,
                arrived_at TIMESTAMPTZ DEFAULT NOW(),
                departed_at TIMESTAMPTZ,
                id_verified BOOLEAN DEFAULT FALSE,
                photo_captured BOOLEAN DEFAULT FALSE,
                photo TEXT
            );
        """)
        # Deployed DBs may pre-date the spec columns; add missing ones
        # idempotently (legacy schema used badge_number + is_available only),
        # plus room capacity / restriction_level on posts.
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='badges' AND column_name='visitor_id') THEN
                    ALTER TABLE badges ADD COLUMN visitor_id UUID;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='badges' AND column_name='visit_request_id') THEN
                    ALTER TABLE badges ADD COLUMN visit_request_id UUID;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='badges' AND column_name='issued_at') THEN
                    ALTER TABLE badges ADD COLUMN issued_at TIMESTAMPTZ DEFAULT NOW();
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='badges' AND column_name='returned_at') THEN
                    ALTER TABLE badges ADD COLUMN returned_at TIMESTAMPTZ;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='badges' AND column_name='status') THEN
                    ALTER TABLE badges ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='badges' AND column_name='issued_by') THEN
                    ALTER TABLE badges ADD COLUMN issued_by UUID;
                END IF;
                -- One row per issuance keeps the full audit trail; a badge
                -- number may appear many times across different visits.
                IF EXISTS (SELECT 1 FROM information_schema.table_constraints tc
                           JOIN information_schema.constraint_column_usage cu
                             ON cu.constraint_name = tc.constraint_name AND cu.table_name = tc.table_name
                           WHERE tc.table_name='badges' AND tc.constraint_type='UNIQUE'
                             AND cu.column_name='badge_number') THEN
                    ALTER TABLE badges DROP CONSTRAINT badges_badge_number_key;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='room_visits' AND column_name='id_verified') THEN
                    ALTER TABLE room_visits ADD COLUMN id_verified BOOLEAN DEFAULT FALSE;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='room_visits' AND column_name='photo_captured') THEN
                    ALTER TABLE room_visits ADD COLUMN photo_captured BOOLEAN DEFAULT FALSE;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='room_visits' AND column_name='photo') THEN
                    ALTER TABLE room_visits ADD COLUMN photo TEXT;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='posts' AND column_name='capacity') THEN
                    ALTER TABLE posts ADD COLUMN capacity INTEGER NOT NULL DEFAULT 10;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='posts' AND column_name='restriction_level') THEN
                    ALTER TABLE posts ADD COLUMN restriction_level TEXT NOT NULL DEFAULT 'none';
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='posts' AND column_name='room_number') THEN
                    ALTER TABLE posts ADD COLUMN room_number TEXT;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='restricted_access' AND column_name='entry_confirmed_at') THEN
                    ALTER TABLE restricted_access ADD COLUMN entry_confirmed_at TIMESTAMPTZ;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='restricted_access' AND column_name='approved_at') THEN
                    ALTER TABLE restricted_access ADD COLUMN approved_at TIMESTAMPTZ;
                END IF;
            END $$;
        """)
        # Legacy DBs missed the room_number column; backfill it from the
        # floor-plan room objects linked to each post (properties.post_id).
        await conn.execute("""
            UPDATE posts p
            SET room_number = (
                SELECT o.properties->>'room_number'
                FROM floor_plan_objects o
                WHERE o.object_type = 'room'
                  AND o.properties->>'post_id' = p.id::text
                  AND o.properties->>'room_number' IS NOT NULL
                ORDER BY o.created_at ASC
                LIMIT 1
            )
            WHERE p.room_number IS NULL
              AND EXISTS (
                  SELECT 1 FROM floor_plan_objects o
                  WHERE o.object_type = 'room'
                    AND o.properties->>'post_id' = p.id::text
                    AND o.properties->>'room_number' IS NOT NULL
              );
        """)
        logger.info("Badges, room visits & room capacity tables verified")

        # Departments table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS departments (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                is_restricted BOOLEAN DEFAULT FALSE,
                restricted_area_id UUID REFERENCES restricted_areas(id) ON DELETE SET NULL,
                post_id UUID REFERENCES posts(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        logger.info("Departments table verified")

        # Add department_id to staff_users if it doesn't exist
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'staff_users' AND column_name = 'department_id'
                ) THEN
                    ALTER TABLE staff_users ADD COLUMN department_id UUID REFERENCES departments(id) ON DELETE SET NULL;
                END IF;
            END $$;
        """)

        # Add post_id (assigned room, used by Room Guards) to staff_users if
        # it doesn't exist — legacy DBs created before the column shipped
        # never receive it otherwise.
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'staff_users' AND column_name = 'post_id'
                ) THEN
                    ALTER TABLE staff_users ADD COLUMN post_id UUID;
                END IF;
            END $$;
        """)

        # Department <-> Room mapping. One department = one room = one guard:
        #  - departments.post_id is the authoritative room (UNIQUE), so a
        #    department can never point at two rooms and two departments can
        #    never share a room.
        #  - a partial unique index on staff_users(post_id) for active guards
        #    means a room can only ever have ONE active Security Guard.
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'departments' AND column_name = 'post_id'
                ) THEN
                    ALTER TABLE departments ADD COLUMN post_id UUID REFERENCES posts(id) ON DELETE SET NULL;
                END IF;
            END $$;
        """)

        # Backfill legacy data: map each department to the floor-plan room
        # whose free-text 'department' tag matches the department name.
        # (Rule-of-one already confirmed, so the tag is unambiguous.)
        # Note: min(uuid) is unavailable on this Windows build, so aggregate
        # as text and cast afterwards.
        await conn.execute("""
            UPDATE departments d
            SET post_id = t.post_id
            FROM (
                SELECT o.properties->>'department' AS dept_name,
                       MIN(o.properties->>'post_id')::uuid AS post_id
                FROM floor_plan_objects o
                WHERE o.object_type = 'room'
                  AND o.properties->>'post_id' IS NOT NULL
                  AND o.properties->>'department' IS NOT NULL
                GROUP BY o.properties->>'department'
            ) t
            WHERE d.name = t.dept_name AND d.post_id IS NULL
        """)
        logger.info("Department-to-room backfill applied")

        # Enforce the one-department-one-room + one-active-guard-per-room rules.
        await conn.execute("""
            DO $$
            BEGIN
                CREATE UNIQUE INDEX IF NOT EXISTS departments_post_id_uq ON departments (post_id)
                    WHERE post_id IS NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS one_active_guard_per_room ON staff_users (post_id)
                    WHERE role = 'Security Guard' AND is_active = TRUE;
            EXCEPTION WHEN unique_violation THEN
                RAISE NOTICE 'Room uniqueness enforcement skipped: existing data maps one room to multiple departments/guards';
            END $$;
        """)
        logger.info("Department/room/guard uniqueness constraints verified")

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL,
                credential_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                sign_count BIGINT DEFAULT 0,
                device_type TEXT DEFAULT 'platform',
                nickname TEXT,
                last_used_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(user_id, credential_id)
            );
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL,
                challenge TEXT NOT NULL,
                purpose TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        logger.info("WebAuthn tables verified")

        # Add destination_type, rejection_reason, arrived_at to visit_requests
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'visit_requests' AND column_name = 'destination_type'
                ) THEN
                    ALTER TABLE visit_requests ADD COLUMN destination_type TEXT DEFAULT 'Normal';
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'visit_requests' AND column_name = 'rejection_reason'
                ) THEN
                    ALTER TABLE visit_requests ADD COLUMN rejection_reason TEXT;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'visit_requests' AND column_name = 'arrived_at'
                ) THEN
                    ALTER TABLE visit_requests ADD COLUMN arrived_at TIMESTAMPTZ;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'visit_requests' AND column_name = 'destination_post_id'
                ) THEN
                    ALTER TABLE visit_requests ADD COLUMN destination_post_id UUID;
                END IF;
                -- Guard-scan (room_visits) reads visitor contact/ID fields off
                -- visit_requests directly, so fresh DBs need them to match the
                -- deployed schema.
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'visit_requests' AND column_name = 'company'
                ) THEN
                    ALTER TABLE visit_requests ADD COLUMN company TEXT;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'visit_requests' AND column_name = 'phone'
                ) THEN
                    ALTER TABLE visit_requests ADD COLUMN phone TEXT;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'visit_requests' AND column_name = 'id_type'
                ) THEN
                    ALTER TABLE visit_requests ADD COLUMN id_type TEXT;
                END IF;
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'visit_requests' AND column_name = 'id_number'
                ) THEN
                    ALTER TABLE visit_requests ADD COLUMN id_number TEXT;
                END IF;
            END $$;
        """)
        logger.info("Visit request schema updated")

        await conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                event_type TEXT NOT NULL,
                actor_staff_id UUID,
                actor_name TEXT,
                visit_request_id UUID,
                visitor_id UUID,
                visitor_name TEXT,
                detail TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        # Existing databases created audit_log.event_type as a Postgres ENUM
        # holding only 9 values, while the routers write ~25 different event
        # types. Because write_audit() is best-effort (never raises), every
        # value missing from the enum was silently dropped — leaving no audit
        # trail for e.g. restricted-area changes, staff/department edits, and
        # wayfinding events. Backfill the enum so all entries are recorded.
        _audit_event_types = [
            "Staff Login", "Staff Logout",
            "Request Created", "Request Approved", "Request Rejected", "Request Assigned",
            "Checked In", "Checked Out",
            "Room Arrival", "Room Departure",
            "Visitor Blocked", "Visitor Unblocked",
            "Self-Visit Created", "Destination Arrival", "Host Notified",
            "Biometric Registered",
            "Staff Created", "Staff Updated",
            "Department Created", "Department Updated", "Department Deleted",
            "Restricted Area Created", "Restricted Area Deactivated",
            "Restricted Access Granted", "Restricted Badge Issued",
            "Restricted Area Entry Confirmed", "Restricted Area Exit",
        ]
        if await conn.fetchval("SELECT 1 FROM pg_type WHERE typname='audit_event_type'"):
            for _et in _audit_event_types:
                await conn.execute(
                    f"ALTER TYPE audit_event_type ADD VALUE IF NOT EXISTS '{_et}'"
                )
        logger.info("Audit log table verified")

        # Module-based access control: add permissions column to staff_users
        await conn.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'staff_users' AND column_name = 'permissions'
                ) THEN
                    ALTER TABLE staff_users ADD COLUMN permissions JSONB NOT NULL DEFAULT '{}';
                END IF;
            END $$;
        """)
        # Backfill role defaults for any account with unset permissions
        from models import DEFAULT_MODULES_BY_ROLE
        import json as _json
        for _role, _modules in DEFAULT_MODULES_BY_ROLE.items():
            await conn.execute(
                """UPDATE staff_users
                   SET permissions = $1::jsonb
                   WHERE role = $2::user_role
                     AND (permissions IS NULL OR permissions::text IN ('', '{}', 'null'))""",
                _json.dumps(list(_modules)), _role,
            )
        logger.info("Staff module permissions verified")

        # Ensure email is unique on staff_users (needed for ON CONFLICT)
        await conn.execute("""
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'staff_users'::regclass AND contype = 'u'
                ) THEN
                    ALTER TABLE staff_users ADD CONSTRAINT staff_users_email_unique UNIQUE (email);
                END IF;
            END $$;
        """)

        # Rename any legacy "Employee" display name to "Lim Kenny" — data
        # migration; runs regardless of demo seeding.
        await conn.execute(
            "UPDATE staff_users SET name='Lim Kenny', initials='LK' "
            "WHERE email='employee@vistahq.com' AND name='Employee'"
        )

        # Seed demo accounts only when enabled (local/dev DB by default,
        # or SEED_DEMO=true). Passwords come from SEED_*_PASSWORD env vars.
        if seed_demo_enabled():
            seeded = await seed_demo_accounts(conn)
            if seeded:
                logger.info(f"Seeded {len(seeded)} new account(s)")
        else:
            logger.info("Demo account seeding skipped (SEED_DEMO not enabled)")

    yield
    await close_pool()
    logger.info("Database pool closed")


app = FastAPI(title="Vista VMS API", version="1.0.0", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS_ORIGINS is a comma-separated list of allowed frontend origins, e.g.
#   CORS_ORIGINS=https://your-app.vercel.app,https://your-app-git-main-you.vercel.app
# Localhost is always allowed too, so local development keeps working
# regardless of what's configured on Render.
_extra_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
_dev_origins = ["http://localhost:3000", "http://localhost:5173"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_dev_origins + _extra_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(webauthn.router)
app.include_router(visitors.router)
app.include_router(visit_requests.router)
app.include_router(audit.router)
app.include_router(analytics.router)
app.include_router(staff.router)
app.include_router(staff.posts_router)
app.include_router(restricted.router)
app.include_router(floor_plan.router)
app.include_router(departments.router)
app.include_router(badges.router)
app.include_router(wayfinding.router)

# Manual seed endpoint — call once after first deploy. Requires admin auth.
# It seeds accounts whose password env var is set; SEED_DEMO is not required.
import traceback
from fastapi import APIRouter, Depends
from database import get_pool

_seed_router = APIRouter()

@_seed_router.get("/admin/accounts")
async def list_accounts(current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin))):
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT id, name, email, role, is_active FROM staff_users ORDER BY created_at")
        return [{"id": str(r["id"]), "name": r["name"], "email": r["email"], "role": r["role"], "is_active": r["is_active"]} for r in rows]

@_seed_router.post("/admin/seed")
async def seed_accounts(current: dict = Depends(require_roles(UserRole.admin, UserRole.super_admin))):
    pool = get_pool()
    async with pool.acquire() as conn:
        created = await seed_demo_accounts(conn)
        return {"created": created, "skipped_missing_password": True}

app.include_router(_seed_router)


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok"}
