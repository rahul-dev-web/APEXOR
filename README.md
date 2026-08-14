# APXOR

APXOR is a security-first Discord anti-nuke platform.

## Current milestone

Phase 1 foundation is implemented:

- FastAPI API
- Discord Gateway client foundation
- SQLAlchemy 2.x async PostgreSQL support
- Supabase/PostgreSQL-compatible database configuration
- Alembic migration foundation
- Initial guild/security configuration models
- Health endpoint
- Docker image
- Pytest smoke tests

## Local setup

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set at minimum:

```env
DISCORD_TOKEN=your_discord_bot_token
DATABASE_URL=your_postgresql_connection_string
```

Run API:

```bash
uvicorn app.main:app --reload
```

Run tests:

```bash
pytest
```

Run database migrations once a PostgreSQL connection is configured:

```bash
alembic upgrade head
```

## Security principles

1. Discord permissions are the first security boundary.
2. AI is advisory, never the root of trust.
3. Gateway events and audit-log correlation are complementary signals.
4. Security actions must be deterministic and idempotent.
5. Recovery reconstructs server state; it cannot resurrect deleted Discord IDs/history.
6. APXOR reports measurable protection state instead of claiming 100% protection.

## Roadmap

1. Foundation
2. Discord Gateway
3. Database
4. Auto Setup
5. Permission Auditor
6. Capability Authorization
7. Anti-Nuke Detection
8. Audit Correlation
9. Snapshots
10. Recovery
11. Lockdown
12. Groq Threat Analyst
13. Dashboard
