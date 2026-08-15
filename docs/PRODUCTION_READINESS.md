# APXOR Production Readiness Checklist

This document tracks the gap between the implemented security MVP and a production Discord deployment.

## Current phase

**Phase 17 — production hardening.**

The security core is implemented; production readiness now depends on environment verification, Discord integration testing, deployment verification, and operational controls.

## Gate matrix

| Gate | Status | Evidence / next action |
| --- | --- | --- |
| Deterministic anti-nuke core | Implemented | Unit/chaos coverage in `tests/` |
| Permission isolation | Implemented | Permission policy + enforcement tests |
| Gateway + audit correlation | Implemented | Gateway/audit tests; production reconnect test remains |
| Incident lifecycle | Implemented | Incident lifecycle tests |
| Snapshot/recovery MVP | Implemented | Recovery tests; broader Discord resource verification remains |
| Groq advisory isolation | Implemented | AI tests + failure isolation |
| Dashboard OAuth foundation | Implemented | Auth/API tests; production browser verification remains |
| Render web/worker topology | Configured | `render.yaml`; deploy verification required |
| Dependency audit | CI configured | GitHub Actions must pass on the branch/main |
| Secret hygiene check | CI configured | No non-example `.env` files may be tracked |
| Discord permission preflight | Implemented | `scripts/discord_preflight.py`; run against a disposable test guild |
| Full Discord integration suite | Pending | Requires a dedicated disposable test guild |
| Gateway reconnect/duplicate/missing event tests | Partially covered | Add live integration coverage |
| Discord 429 recovery | Unit-level coverage | Verify against live API rate-limit behavior |
| Database outage/reconnect | Unit/chaos coverage | Verify against real Supabase/PostgreSQL |
| Recovery partial-failure verification | Unit/chaos coverage | Verify with disposable Discord resources |
| Third-party bot/integration scenarios | Pending live test | Exercise role/bot/webhook threat cases |
| Production observability | Pending | Logs, metrics, alerting and incident escalation |
| Render health-check verification | Pending | Confirm `/health` and worker startup after deployment |

## Read-only Discord preflight

Before any live integration test, run the preflight against a **disposable test guild**:

```powershell
python -m scripts.discord_preflight --guild-id <TEST_GUILD_ID>
```

The check validates the bot's effective permissions, role hierarchy and owner hierarchy. It does **not** create, delete, edit, or recover Discord resources and it never prints the bot token.

A successful preflight is necessary but not sufficient for production readiness. It only verifies the Discord-side prerequisites that can be checked safely without executing a destructive scenario.

## Render topology

APXOR uses two processes:

- **Web service:** FastAPI dashboard/API and `/health` endpoint.
- **Background worker:** Discord Gateway client and security event runtime.

Both services use the repository `Dockerfile`. The web service runs `alembic upgrade head` before starting Uvicorn. The worker only starts the Discord bot and does not run migrations.

All production secrets are declared as unsynchronized Render environment variables in `render.yaml`. They must be entered through Render's secret/environment configuration and must never be committed to Git.

## Required production environment

```text
DISCORD_TOKEN
DATABASE_URL
GROQ_API_KEY
GROQ_MODEL
DASHBOARD_API_KEY
DISCORD_CLIENT_ID
DISCORD_CLIENT_SECRET
DISCORD_REDIRECT_URI
DASHBOARD_FRONTEND_URL
DASHBOARD_SESSION_SECRET
APP_ENV=production
```

## Discord integration test policy

Use a disposable test guild. Never run destructive recovery tests against a real production community.

Minimum live scenarios:

1. Unauthorized critical permission grant.
2. Rapid channel deletion.
3. Rapid role deletion.
4. Protected APXOR resource modification.
5. Audit-log actor attribution.
6. Duplicate gateway signal.
7. Gateway reconnect during an incident.
8. Discord 429 during recovery.
9. Partial recovery failure.
10. Third-party bot/integration privilege escalation.

For each scenario verify:

```text
Detect -> Attribute -> Score -> Contain -> Notify -> Recover -> Verify -> Persist
```

## Release rule

Do not label APXOR `PROTECTED` in a production deployment until the required Discord permissions, role hierarchy, database, Gateway worker, snapshot health, notification path and reconciliation loop have all been verified.

Do not claim 100% protection. APXOR protects according to Discord's permission and API constraints and reports degraded states when those guarantees are not available.
