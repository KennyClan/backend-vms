# Vista VMS — Backend

FastAPI + asyncpg + PostgreSQL

## Setup

```bash
cp .env.example .env
# Edit .env with your DATABASE_URL and a strong SECRET_KEY

pip install -r requirements.txt

# Run the DB schema first:
psql -U postgres -d vista_vms -f ../database/vista_vms_schema.sql

uvicorn main:app --reload --port 8000
```

API docs: http://localhost:8000/docs

## Demo credentials (after seeding with real bcrypt hashes)

| Role           | Email                    |
|----------------|---------------------------|
| Administrator  | admin@vistahq.com        |
| Security Guard | security@vistahq.com     |
| Receptionist   | reception@vistahq.com    |

Choose your own passwords and generate real hashes — never ship a demo
deployment with a guessable password like `admin123`:
```bash
python -c "from passlib.context import CryptContext; ctx=CryptContext(schemes=['bcrypt']); print(ctx.hash('YOUR-CHOSEN-PASSWORD'))"
```
