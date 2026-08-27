import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from database import create_pool, close_pool
from routers import auth, visitors, visit_requests, audit, analytics, webauthn, staff, restricted, floor_plan, departments
import logging
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from limiter import limiter
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_pool()
    logger.info("Database pool created")
    # Auto-create floor plan tables if they don't exist
    from database import get_pool
    pool = get_pool()
    async with pool.acquire() as conn:
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
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        logger.info("Restricted area & post tables verified")

        # Departments table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS departments (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                is_restricted BOOLEAN DEFAULT FALSE,
                restricted_area_id UUID REFERENCES restricted_areas(id) ON DELETE SET NULL,
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
        logger.info("Audit log table verified")
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


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok"}
