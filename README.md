# APXOR

APXOR is a security-first Discord anti-nuke platform.

## Current implementation status

**Overall: ~40% of the backend security MVP architecture is now implemented.**

This is an engineering progress estimate, not a claim that the bot is production-ready.

### Implemented

- FastAPI API foundation + health endpoint
- Discord Gateway client foundation with guild/role/channel/guild-update monitoring
- SQLAlchemy 2.x async PostgreSQL support
- Supabase/PostgreSQL-compatible database configuration
- Alembic migration foundation + initial security/event schemas
- Guild and security configuration persistence
- Deterministic event normalization and short-window velocity correlation
- Event fingerprinting / duplicate suppression
- Baseline risk scoring with protected-resource weighting
- Audit-log correlation foundation
- Database-backed protected roles/channels lookup
- Deterministic emergency lockdown engine
- Conservative privileged-permission auditing
- **Idempotent guild auto-setup**: APXOR security role, security category, alert/critical/audit/recovery channels, protected-resource registration, and initial `PROTECTED` state
- Docker image + pytest smoke/security-core tests

### Not yet implemented

- Capability authorization and APXOR-mediated operator commands
- Full Discord permission isolation/enforcement policy
- Complete Gateway audit-event coverage and robust actor correlation
- Continuous versioned Discord snapshots
- Channel/role state reconstruction and recovery queue
- Incident aggregation and owner notification delivery
- Emergency lockdown state machine beyond the current containment primitive
- Groq threat analyst / structured AI decisions
- `/ai` command and AI channel
- Dashboard API
- Dashboard frontend
- Production worker/queue separation
- Chaos/security integration test suite

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

## Auto-setup behavior

When APXOR connects to a guild (or joins one), it attempts an idempotent security bootstrap:

1. Ensure the guild record and security configuration exist.
2. Create/reuse the `APXOR-SECURITY` role with no destructive Discord permissions.
3. Create/reuse the `APXOR SECURITY` category.
4. Create/reuse `#apxor-alerts`, `#apxor-critical`, `#apxor-audit`, and `#apxor-recovery`.
5. Register the security role/channels as protected resources.
6. Mark the guild `PROTECTED` only after the bootstrap succeeds.

**Safety rule:** auto-setup does not silently remove existing administrator or moderation permissions from human roles. Existing privileged roles are audited and logged; permission enforcement will be an explicit next phase.

APXOR must still be invited with the Discord permissions required for the operations it is expected to perform, and its role must be high enough in the guild hierarchy to manage the resources it owns.

## Security principles

1. Discord permissions are the first security boundary.
2. AI is advisory, never the root of trust.
3. Gateway events and audit-log correlation are complementary signals.
4. Security actions must be deterministic and idempotent.
5. Recovery reconstructs server state; it cannot resurrect deleted Discord IDs/history.
6. APXOR reports measurable protection state instead of claiming 100% protection.
7. Auto-setup is conservative and never silently strips user permissions.

## Roadmap

1. Foundation — **implemented**
2. Discord Gateway — **foundation implemented; coverage expanding**
3. Database — **implemented**
4. Auto Setup — **implemented**
5. Permission Auditor — **foundation implemented**
6. Capability Authorization — next
7. Anti-Nuke Detection — **foundation implemented; hardening next**
8. Audit Correlation — **foundation implemented; hardening next**
9. Snapshots — next
10. Recovery — next
11. Lockdown — **containment primitive implemented**
12. Groq Threat Analyst — next
13. Dashboard — next
