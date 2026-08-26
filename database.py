import os
import asyncpg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost/vista_vms")
_pool: asyncpg.Pool | None = None

# Supabase (and most managed Postgres providers) require SSL and, if you're
# using the connection pooler (PgBouncer in transaction mode), don't support
# server-side prepared statements. We detect "not localhost" as "probably a
# managed cloud DB" and adjust accordingly. This still works fine against a
# plain local Postgres.
_is_local = "localhost" in DATABASE_URL or "127.0.0.1" in DATABASE_URL
_url_has_sslmode = "sslmode=" in DATABASE_URL
_statement_cache_size = 0 if not _is_local else 100  # 0 = safe with PgBouncer/Supabase pooler


async def create_pool():
    global _pool
    kwargs = dict(min_size=1, max_size=10, statement_cache_size=_statement_cache_size, command_timeout=60)
    # Only pass ssl= explicitly if the DSN itself doesn't already specify
    # sslmode, since asyncpg rejects having both set.
    if not _is_local and not _url_has_sslmode:
        kwargs["ssl"] = "require"
    _pool = await asyncpg.create_pool(DATABASE_URL, **kwargs)


async def close_pool():
    if _pool:
        await _pool.close()


def get_pool():
    return _pool


async def get_conn():
    pool = _pool
    async with pool.acquire() as conn:
        yield conn
