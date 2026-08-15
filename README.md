# APXOR

APXOR is a security-first Discord anti-nuke platform.

## Current implementation status

**Backend security MVP: ~95% implemented.**

**Overall APXOR v1 engineering scope: ~82–86% implemented.**

These are engineering progress estimates, not production-readiness claims. The deterministic security core, recovery lifecycle, AI advisory layer, dashboard API/authentication foundation, and operational health checks are substantially implemented. Live Discord integration/chaos verification, broader command/resource coverage, production observability and deployment verification remain.

### Implemented

- FastAPI API foundation + liveness/readiness/deep health endpoints
- SQLAlchemy 2.x async PostgreSQL support with Supabase-compatible configuration
- Alembic migrations with a single merged head
- Discord Gateway monitoring for guild, role, channel, audit-log, webhook and integration activity
- Deterministic event normalization, duplicate suppression and short-window velocity correlation
- Deterministic privilege-escalation scoring; `ADMINISTRATOR` reaches emergency risk without AI
- Real-time Discord audit-log Gateway normalization with actor/target/audit-ID correlation
- REST audit-log fallback with stale-entry rejection when `created_at` is available
- Protected-resource lookup and deterministic emergency lockdown
- Conservative permission auditing and explicit permission enforcement with reconciliation
- Idempotent guild auto-setup with protected APXOR security resources
- Server-side capability authorization with owner authority, guild-scoped grants and expiry support
- Authorized APXOR slash commands for security, channel, role and moderation management
- Versioned Discord snapshots and dependency-aware, priority-aware, rate-limit-aware recovery
- Automatic high-risk channel/role recovery
- Role-membership snapshot/recovery support
- Deterministic incident aggregation and severity escalation
- Durable recovery batch accounting; incidents remain open until the complete target set is verified
- Protected alert delivery and owner DM escalation for high/critical/emergency detections
- Advisory Groq threat analysis with strict structured output, input hashing and asynchronous execution
- Persistent AI threat-assessment audit records
- AI failure isolation: Groq cannot block deterministic detection, lockdown, notification or recovery
- Deterministic security decision kernel separating event risk from enforcement policy
- Explicit protection state machine with recovery success/failure/degraded transitions
- `ProtectionRuntime` wired into the Discord Gateway event path
- Unit/chaos-style tests covering security core, permissions, audit correlation, AI, privilege escalation, decision kernel, protection runtime, incident lifecycle and dashboard authentication/API behavior
- Docker image + GitHub Actions compile/test workflow
- React/Vite dashboard foundation
- Discord OAuth dashboard login with signed HttpOnly session cookies
- Guild-scoped dashboard authorization based on Discord owner/admin/manage-guild access
- Authenticated security overview with protection score, metrics, health and navigation
- Dashboard views for security, incidents, events, recovery, snapshots and AI data
- Safe dependency health snapshot exposing database, AI and dashboard-auth readiness without returning secret values

### Remaining

- Complete APXOR command coverage for advanced editing, moderation, snapshots, recovery and configuration
- `/ai ask` conversational security analyst and dedicated AI channel
- Broader Discord resource recovery and verification coverage
- Production external queue / worker separation
- Reconciliation hardening for all eventually-consistent Discord audit/resource cases
- Full live Discord integration and chaos test suite
- Production observability, alerting and deployment verification
- Dashboard write workflows with production-grade CSRF/mutation policy
- Dashboard UX expansion beyond the current security overview/data views

## Local setup

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\\.venv\\Scripts\\Activate.ps1
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
DISCORD_CLIENT_ID=your_discord_oauth_client_id
DISCORD_CLIENT_SECRET=your_discord_oauth_client_secret
DISCORD_REDIRECT_URI=https://api.example.com/api/dashboard/auth/callback
DASHBOARD_FRONTEND_URL=https://dashboard.example.com
DASHBOARD_SESSION_SECRET=use-a-long-random-secret
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

## Operational health

- `/health` is a liveness check and does not require external dependencies.
- `/health/ready` verifies PostgreSQL connectivity and is suitable for Render readiness checks.
- `/health/deep` returns a non-secret dependency snapshot for database, Groq configuration and dashboard session configuration. It returns HTTP 503 when any of those dependencies are not ready.

The deep endpoint intentionally reports configuration state only; it never returns API keys, OAuth secrets or session-secret values.

## Dashboard authentication

The browser-facing dashboard uses Discord OAuth and a signed, HttpOnly session cookie. The backend validates the authenticated Discord principal against the guild IDs returned by Discord OAuth and only exposes a guild to owners or users with `ADMINISTRATOR`/`MANAGE_GUILD` access.

The `DASHBOARD_API_KEY` path remains available for trusted server-to-server tooling and tests. **Never expose this secret to browser code.**

Current dashboard endpoints include:

```text
GET  /api/dashboard/auth/login
GET  /api/dashboard/auth/callback
GET  /api/dashboard/auth/me
POST /api/dashboard/auth/logout

GET /api/dashboard/health
GET /api/dashboard/guilds/{guild_id}/overview
GET /api/dashboard/guilds/{guild_id}/security
GET /api/dashboard/guilds/{guild_id}/incidents
GET /api/dashboard/guilds/{guild_id}/events
GET /api/dashboard/guilds/{guild_id}/ai
GET /api/dashboard/guilds/{guild_id}/recovery
GET /api/dashboard/guilds/{guild_id}/snapshots
```

Future dashboard mutation endpoints must add explicit CSRF/session mutation protection and server-side capability authorization before production use.

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

Permission enforcement is configuration-controlled. Role updates are enforced immediately and the entire guild is periodically reconciled.

## Anti-nuke detection

The deterministic engine tracks repeated and mixed destructive activity and treats privilege grants as first-class security signals:

| Signal | Baseline risk |
|---|---:|
| `ADMINISTRATOR` grant | 95 / EMERGENCY |
| `MANAGE_GUILD` / `MANAGE_CHANNELS` / `MANAGE_ROLES` | 85 / HIGH |
| `MANAGE_WEBHOOKS` | 80 / CRITICAL |
| Rapid destructive actions | velocity-based escalation |
| Protected-resource modification | protected-target escalation |

Detection does not depend on AI availability.

## Audit correlation

APXOR consumes Discord's real-time audit-log Gateway signal when available and uses REST Audit Logs as a fallback for resource events. Audit IDs become stable fingerprints so duplicate Gateway/resource signals do not trigger duplicate security actions. REST fallback correlation rejects stale entries when `created_at` is available, reducing incorrect actor attribution from eventually-consistent reads.

## Incident and recovery model

High-risk events are grouped into short-lived incidents by guild, actor and attack family. Incident severity escalates deterministically. Recovery uses known-good snapshots and reconstructs Discord state; it cannot resurrect deleted Discord IDs or message history.

Recovery is priority-aware and rate-limit-aware. Protected security resources receive higher priority. Multi-resource recovery is tracked as a durable batch: APXOR counts unique destructive targets, keeps the incident open while siblings remain pending, and only transitions to `PROTECTED` after the complete batch is verified. A failed target keeps the incident open for follow-up recovery.

## Protection state lifecycle

```text
INITIALIZING -> PROTECTED
PROTECTED -> SUSPICIOUS -> HIGH_RISK -> LOCKDOWN
HIGH_RISK/LOCKDOWN -> RECOVERING
RECOVERING -> PROTECTED | DEGRADED | RECOVERY_FAILED
RECOVERY_FAILED -> RECOVERING | LOCKDOWN | DEGRADED
```

A later low-risk event cannot silently clear active `LOCKDOWN`, `RECOVERING`, or `RECOVERY_FAILED` states.

## AI security boundary

The Groq threat analyst receives normalized security context only. Its output is schema-constrained and persisted for auditability. AI recommendations are advisory and are never executed as arbitrary Discord operations.

The security pipeline launches AI analysis asynchronously after deterministic event persistence, so model latency or failure cannot block containment or recovery.

## Branch policy

APXOR follows a **single-main-branch workflow**. `main` is the canonical development branch.

Existing feature branches are not treated as parallel development lines. Before deleting them, verify that they contain no commits ahead of `main`. As of the current repository state, the only branch is `main`, so there are no branches to merge or clean up.

## Roadmap

1. Foundation — **implemented**
2. Discord Gateway — **implemented; reconciliation hardening next**
3. Database — **implemented**
4. Auto Setup — **implemented**
5. Permission Auditor — **implemented; policy expansion next**
6. Capability Authorization — **implemented; command coverage expanding**
7. Anti-Nuke Detection — **implemented; behavior hardening next**
8. Audit Correlation — **Gateway + REST fallback implemented; broader reconciliation next**
9. Snapshots — **implemented; broader resource coverage next**
10. Recovery — **MVP lifecycle implemented; broader resource verification next**
11. Lockdown — **implemented**
12. Incident Engine — **implemented**
13. Groq Threat Analyst — **implemented as advisory runtime + persistence**
14. `/ai` — **status + incident implemented; conversational interface next**
15. Dashboard API — **implemented**
16. Dashboard authentication/frontend foundation — **implemented; UX and write workflows next**
17. Production/integration/chaos testing — **in progress; operational health hardening added**
18. Production observability and deployment verification — **pending**

See [`docs/SECURITY_SPEC_V1.md`](docs/SECURITY_SPEC_V1.md) for the frozen v1 security boundary and production-readiness gates.
