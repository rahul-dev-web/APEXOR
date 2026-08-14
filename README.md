# APXOR

APXOR is a security-first Discord anti-nuke platform.

## Current implementation status

**Overall: ~92% of the backend security MVP architecture is now implemented.**

This is an engineering progress estimate, not a claim that the bot is production-ready.

### Implemented

- FastAPI API foundation + health endpoint
- Authenticated dashboard security API (service-to-service API key for MVP)
- Discord Gateway monitoring for guild, role, channel, audit-log, webhook and integration activity
- SQLAlchemy 2.x async PostgreSQL support with Supabase-compatible configuration
- Alembic migrations with a single merged head after Phase 1 parallel migration work
- Guild/security configuration persistence
- Deterministic event normalization, duplicate suppression and short-window velocity correlation
- Deterministic privilege-escalation scoring: `ADMINISTRATOR` reaches emergency risk without AI
- Real-time Discord audit-log Gateway normalization with actor/target/audit-ID correlation
- Protected-resource lookup and deterministic emergency lockdown
- Conservative permission auditing and explicit permission enforcement with five-minute reconciliation
- Idempotent guild auto-setup with protected APXOR security resources
- Server-side capability authorization with owner authority, guild-scoped grants and expiry support
- Authorized APXOR slash commands for security, channel, role and moderation management
- Read-only `/ai status` and `/ai incident` commands backed by persisted advisory assessments
- Versioned Discord snapshots and dependency-aware, priority-aware, rate-limit-aware recovery
- Automatic recovery for high-risk channel/role deletion
- Deterministic incident aggregation in the persistence layer with short correlation windows and severity escalation
- Protected alert delivery and owner DM escalation for high/critical/emergency detections
- Advisory Groq threat analysis with strict structured output, input hashing and asynchronous execution
- Persistent `ai_threat_assessments` audit records for AI analysis
- AI failure isolation: Groq cannot block deterministic detection, lockdown, notification or recovery
- Deterministic security decision kernel separating event risk from enforcement policy
- Explicit protection state machine with recovery success/failure/degraded transitions
- `ProtectionRuntime` wired into the Discord Gateway event path as the lifecycle policy boundary
- Protected-resource containment correctly persists `LOCKDOWN` even when the raw risk band is lower
- Security-core, permission, audit, AI, privilege-escalation, decision-kernel, protection-runtime and dashboard-auth unit tests
- Docker image + GitHub Actions compile/test workflow

### Not yet implemented

- Complete APXOR command coverage for advanced editing, moderation, snapshots, recovery and configuration
- `/ai ask` conversational security analyst and dedicated AI channel
- Role-member assignment restoration and broader Discord resource recovery verification
- Full recovery lifecycle orchestration through the protection state machine
- Dashboard end-user authentication/session layer and frontend
- Production external queue / worker separation
- Reconciliation hardening for all eventually-consistent Discord audit/resource cases
- Full Discord integration/chaos test suite
- Production observability, alerting and deployment verification

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

Configure:

```env
DISCORD_TOKEN=your_discord_bot_token
DATABASE_URL=your_postgresql_connection_string
GROQ_API_KEY=your_groq_api_key
GROQ_MODEL=meta-llama/llama-4-scout-17b-16e-instruct
DASHBOARD_API_KEY=your-dashboard-service-secret
```

Run the API:

```bash
uvicorn app.main:app --reload
```

Run the Discord worker:

```bash
python -m app.bot.runner
```

Run tests:

```bash
pytest
```

Run migrations:

```bash
alembic upgrade head
```

## Dashboard API

The backend now exposes read-only security data for a future dashboard frontend. The MVP uses a server-side `DASHBOARD_API_KEY` and expects it in the `X-APXOR-Dashboard-Key` header.

Endpoints:

```text
GET /api/dashboard/health
GET /api/dashboard/guilds/{guild_id}/security
GET /api/dashboard/guilds/{guild_id}/incidents
GET /api/dashboard/guilds/{guild_id}/events
GET /api/dashboard/guilds/{guild_id}/ai
GET /api/dashboard/guilds/{guild_id}/recovery
GET /api/dashboard/guilds/{guild_id}/snapshots
```

This is intentionally service-level authentication only. A browser-facing OAuth/session model is a separate dashboard phase and should not be replaced by exposing the service secret to untrusted clients.

## Security architecture

APXOR uses deterministic controls as the root of trust:

```text
Discord Gateway + Audit Logs
            |
            v
     Event Normalization
            |
            v
   Permission / Rule Engine
            |
            v
      Risk + Correlation
            |
            v
   Deterministic Decision Kernel
            |
            v
      Protection Runtime
            |
      +-----+-----+
      |           |
      v           v
 Lockdown      Recovery
      |
      v
 Notifications
      |
      +----> Groq advisory analysis
                    |
                    v
             AI audit storage
```

Groq never receives Discord tool access and never authorizes a security mutation. If Groq is unavailable, APXOR continues using deterministic rules.

## Permission isolation

Discord permissions are APXOR's first security boundary. The default critical policy prohibits `ADMINISTRATOR`, `MANAGE_GUILD`, `MANAGE_CHANNELS`, `MANAGE_ROLES`, and `MANAGE_WEBHOOKS` on manageable non-owner roles. Enforcement never rewrites `@everyone`, managed/integration roles, roles at or above APXOR's hierarchy, or the guild owner's top role.

Permission enforcement is configuration-controlled. When enabled, role updates are enforced immediately and the entire guild is reconciled every five minutes.

## Anti-nuke detection

The deterministic engine tracks both repeated and mixed destructive activity. It also treats privilege grants as first-class security signals:

| Signal | Baseline risk |
|---|---:|
| `ADMINISTRATOR` grant | 95 / EMERGENCY |
| `MANAGE_GUILD` / `MANAGE_CHANNELS` / `MANAGE_ROLES` | 85 / HIGH |
| `MANAGE_WEBHOOKS` | 80 / CRITICAL |
| Rapid destructive actions | velocity-based escalation |
| Protected-resource modification | protected-target escalation |

Detection does not depend on AI availability.

## Audit correlation

APXOR consumes Discord's real-time audit-log Gateway signal when available and uses REST Audit Logs as a fallback for resource events. Audit IDs become stable fingerprints so duplicate Gateway/resource signals do not trigger duplicate security actions.

## Incident and recovery model

High-risk events are grouped into short-lived incidents by guild, actor and attack family. Incident severity escalates deterministically. Recovery uses known-good snapshots and reconstructs Discord state; it cannot resurrect deleted Discord IDs or message history.

Recovery is single-worker, priority-aware and rate-limit-aware. Protected security resources receive higher priority.

## Protection state lifecycle

The protection lifecycle is explicit and deterministic:

```text
INITIALIZING -> PROTECTED
PROTECTED -> SUSPICIOUS -> HIGH_RISK -> LOCKDOWN
HIGH_RISK/LOCKDOWN -> RECOVERING
RECOVERING -> PROTECTED | DEGRADED | RECOVERY_FAILED
RECOVERY_FAILED -> RECOVERING | LOCKDOWN | DEGRADED
```

A later low-risk event cannot silently clear active `LOCKDOWN`, `RECOVERING`, or `RECOVERY_FAILED` states. Protected-resource containment can enter `LOCKDOWN` even when the ordinary risk band would otherwise be `SUSPICIOUS`.

## AI security boundary

The Groq threat analyst receives normalized security context only. Its output is schema-constrained and persisted for auditability. AI recommendations are advisory and are never executed as arbitrary Discord operations.

The security pipeline launches AI analysis asynchronously after deterministic event persistence, so model latency or failure cannot block containment or recovery.

## Roadmap

1. Foundation — **implemented**
2. Discord Gateway — **implemented; reconciliation hardening next**
3. Database — **implemented; migration heads merged**
4. Auto Setup — **implemented**
5. Permission Auditor — **implemented; policy expansion next**
6. Capability Authorization — **implemented; command coverage expanding**
7. Anti-Nuke Detection — **implemented; behavior hardening next**
8. Audit Correlation — **real-time Gateway + REST fallback implemented; reconciliation hardening next**
9. Snapshots — **implemented; broader resource coverage next**
10. Recovery — **dependency/rate-limit/priority MVP implemented; verification expansion next**
11. Lockdown — **deterministic state machine + Gateway runtime integration implemented; full recovery lifecycle next**
12. Incident Engine — **implemented; richer incident lifecycle next**
13. Groq Threat Analyst — **runtime + persistence implemented**
14. `/ai` — **status + incident implemented; conversational interface next**
15. Dashboard API — **read-only security API implemented; end-user auth next**
16. Dashboard frontend — **next**
17. Production/chaos testing — **next**
