# APXOR

APXOR is a security-first Discord anti-nuke platform.

## Current implementation status

**Overall: ~70% of the backend security MVP architecture is now implemented.**

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
- **Authorized APXOR slash-command layer** with server-side capability checks
- **Security capability management commands** for owner/security operators to grant and revoke APXOR capabilities
- **Channel operations** (`/channel create`, `/channel delete`) routed through APXOR authorization
- **Role operations** (`/role create`, `/role delete`) routed through APXOR authorization and Discord hierarchy checks
- **Security status command** (`/security status`) with guild protection state and score
- **Versioned Discord security snapshots** for guilds, roles, and channels, including permission overwrites and recoverable channel/role metadata
- **Event-driven snapshot capture** before deletes/updates and after safe creates/updates
- **Snapshot-based recovery engine** with auditable recovery actions and idempotent existing-resource checks
- **Priority-aware recovery orchestrator** with a single worker, bounded queue, protected-resource priority, lifecycle management, and a replaceable queue boundary
- **Automatic recovery trigger** for high-risk channel/role deletion events
- **Configuration-driven anti-nuke enforcement** honoring per-guild enable/disable flags and high/critical/emergency risk thresholds
- **Protected security alert delivery** to the APXOR critical channel and, for critical/emergency incidents, the guild owner via DM when enabled
- **Recovery/lockdown feature flags** are enforced by the event pipeline
- Recovery orchestrator unit tests covering priority ordering and lifecycle behavior
- Docker image + pytest smoke/security-core tests

### Not yet implemented

- Complete APXOR command coverage for role editing, channel editing, moderation, snapshots, recovery, and configuration
- Complete Discord permission isolation/enforcement policy
- Complete Gateway audit-event coverage and robust actor correlation
- Multi-resource recovery dependency ordering (category → channel → permissions)
- Role-member assignment restoration
- Incident aggregation/deduplication beyond event-level incident creation
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

## Capability authorization and commands

APXOR capabilities are server-side permissions independent of Discord role names. The current command layer exposes:

- `/security status`
- `/security grant`
- `/security revoke`
- `/channel create`
- `/channel delete`
- `/role create`
- `/role delete`

The owner is the root authority. Non-owners need an explicit, enabled, non-expired capability grant. `/security grant` and `/security revoke` require `SECURITY_MANAGE`, so delegation remains server-side and auditable. Destructive commands additionally require explicit confirmation and Discord role/channel hierarchy checks.

The command tree is synchronized per guild on startup/join so development and newly joined servers receive commands without waiting for global command propagation.

## Snapshot and recovery model

Snapshots are immutable versions keyed by resource identity. The event pipeline deliberately snapshots the **known-good state before updates/deletes**. Safe updates then advance the snapshot to the new state. Suspicious updates do not replace the known-good recovery source with the potentially malicious state.

The current snapshot records:

- guild security metadata
- role names, permissions, position, colour, hoist and mentionable state
- channel type, name, parent, position and supported channel settings
- role/member permission overwrites where the target still exists

Recovery reconstructs state by creating a replacement Discord resource. It does **not** claim to resurrect the original Discord ID or message history. Each recovery attempt is recorded in `recovery_actions` with its source snapshot, status and error state.

High-risk role/channel deletion events are placed onto the priority recovery queue. Protected resources receive higher recovery priority. The current queue is intentionally in-memory for the MVP so the security boundary remains simple; it can later be backed by Redis or Render queue infrastructure.

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
11. Per-guild risk thresholds and feature flags are authoritative for runtime security decisions.
12. Critical/emergency notifications use protected APXOR channels and owner DM escalation when configured.
13. APXOR-controlled destructive operations require explicit capability authorization and confirmation.

## Roadmap

1. Foundation — **implemented**
2. Discord Gateway — **foundation implemented; coverage expanding**
3. Database — **implemented**
4. Auto Setup — **implemented**
5. Permission Auditor — **foundation implemented**
6. Capability Authorization — **command wiring implemented; complete command coverage next**
7. Anti-Nuke Detection — **foundation implemented; configuration/notification hardening implemented; behavior hardening next**
8. Audit Correlation — **foundation implemented; hardening next**
9. Snapshots — **event-driven MVP implemented; reconciliation next**
10. Recovery — **engine + priority orchestration implemented; dependency/rate-limit hardening next**
11. Lockdown — **containment primitive implemented; state machine next**
12. Groq Threat Analyst — next
13. Dashboard — next
