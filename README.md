# APXOR

APXOR is a security-first Discord anti-nuke platform.

## Current implementation status

**Overall: ~62% of the backend security MVP architecture is now implemented.**

This is an engineering progress estimate, not a claim that the bot is production-ready.

### Implemented

- FastAPI API foundation + health endpoint
- Discord Gateway client foundation with guild/role/channel/guild-update monitoring
- SQLAlchemy 2.x async PostgreSQL support
- Supabase/PostgreSQL-compatible database configuration
- Alembic migration foundation through `0005_recovery_actions`
- Guild and security configuration persistence
- Deterministic event normalization and short-window velocity correlation
- Event fingerprinting / duplicate suppression
- Baseline risk scoring with protected-resource weighting
- Audit-log correlation foundation
- Database-backed protected roles/channels lookup
- Deterministic emergency lockdown engine
- Conservative privileged-permission auditing
- Idempotent guild auto-setup: APXOR security role, security category, alert/critical/audit/recovery channels, protected-resource registration, and initial `PROTECTED` state
- Server-side capability authorization foundation: owner authority, guild-scoped grants, expiry support, grant/revoke rules, and database uniqueness constraints
- **Versioned Discord security snapshots** for guilds, roles, and channels, including permission overwrites and recoverable channel/role metadata
- **Event-driven snapshot capture** before deletes/updates and after safe creates/updates
- **Snapshot-based recovery engine** with auditable recovery actions and idempotent existing-resource checks
- **Priority-aware recovery orchestrator** with a single worker, bounded queue, protected-resource priority, lifecycle management, and a replaceable queue boundary
- **Automatic recovery trigger** for high-risk channel/role deletion events
- **Recovery orchestrator unit tests** covering priority ordering and lifecycle behavior
- Docker image + pytest smoke/security-core tests

### Not yet implemented

- APXOR slash-command authorization wiring (`/channel`, `/role`, moderation commands)
- Complete Discord permission isolation/enforcement policy
- Complete Gateway audit-event coverage and robust actor correlation
- Multi-resource recovery dependency ordering (category → channel → permissions)
- Role-member assignment restoration
- Incident aggregation and owner notification delivery
- Emergency lockdown state machine beyond the current containment primitive
- Groq threat analyst / structured AI decisions
- `/ai` command and AI channel
- Dashboard API
- Dashboard frontend
- Production external queue / worker separation
- Discord API rate-limit aware recovery backoff and verification hardening
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
6. Capture the first recoverable guild/role/channel baseline when snapshots are enabled.
7. Mark the guild `PROTECTED` only after the bootstrap succeeds.

**Safety rule:** auto-setup does not silently remove existing administrator or moderation permissions from human roles. Existing privileged roles are audited and logged; permission enforcement will be an explicit next phase.

APXOR must still be invited with the Discord permissions required for the operations it is expected to perform, and its role must be high enough in the guild hierarchy to manage the resources it owns.

## Snapshot and recovery model

Snapshots are immutable versions keyed by resource identity. The event pipeline deliberately snapshots the **known-good state before updates/deletes**. Safe updates then advance the snapshot to the new state. Suspicious updates do not replace the known-good recovery source with the potentially malicious state.

The current snapshot records:

- guild security metadata
- role names, permissions, position, colour, hoist and mentionable state
- channel type, name, parent, position and supported channel settings
- role/member permission overwrites where the target still exists

Recovery reconstructs state by creating a replacement Discord resource. It does **not** claim to resurrect the original Discord ID or message history. Each recovery attempt is recorded in `recovery_actions` with its source snapshot, status and error state.

High-risk role/channel deletion events are placed onto the priority recovery queue. Protected resources receive higher recovery priority. The current queue is intentionally in-memory for the MVP so the security boundary remains simple; it can later be backed by Redis or Render queue infrastructure.

## Capability authorization

APXOR capabilities are server-side permissions independent of Discord role names. The authorization service currently supports:

- owner bypass based on the persisted guild owner ID
- explicit guild-scoped user grants
- capability expiry timestamps
- deterministic grant/revoke checks
- `SECURITY_MANAGE` delegation for non-owner security operators
- database uniqueness to prevent duplicate active grants

The next step is wiring these gates into actual APXOR slash commands and dashboard APIs. The browser/UI must never be treated as the authorization boundary.

## Security principles

1. Discord permissions are the first security boundary.
2. AI is advisory, never the root of trust.
3. Gateway events and audit-log correlation are complementary signals.
4. Security actions must be deterministic and idempotent.
5. Security snapshots preserve known-good state before potentially destructive mutations.
6. Recovery reconstructs server state; it cannot resurrect deleted Discord IDs/history.
7. APXOR reports measurable protection state instead of claiming 100% protection.
8. Auto-setup is conservative and never silently strips user permissions.
9. Dashboard/client input is untrusted; privileged operations require server-side authorization.
10. Recovery is queued and bounded instead of issuing uncontrolled concurrent Discord REST mutations.

## Roadmap

1. Foundation — **implemented**
2. Discord Gateway — **foundation implemented; coverage expanding**
3. Database — **implemented**
4. Auto Setup — **implemented**
5. Permission Auditor — **foundation implemented**
6. Capability Authorization — **foundation implemented; command/API wiring next**
7. Anti-Nuke Detection — **foundation implemented; hardening next**
8. Audit Correlation — **foundation implemented; hardening next**
9. Snapshots — **event-driven MVP implemented; reconciliation next**
10. Recovery — **engine + priority orchestration implemented; dependency/rate-limit hardening next**
11. Lockdown — **containment primitive implemented**
12. Groq Threat Analyst — next
13. Dashboard — next
