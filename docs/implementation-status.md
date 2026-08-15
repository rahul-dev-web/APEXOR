# APXOR Implementation Status

> Updated after commit `2a08c52948e972bcdfeb4e29914f266877d5fc65`.

## Current progress

**Backend security MVP: ~97% of the planned architecture implemented.**

This percentage measures implementation coverage of the agreed backend/security architecture. It is **not** a production-readiness percentage and does not mean APXOR can guarantee prevention of every Discord-level destructive action.

## Completed

- FastAPI application and health endpoint
- Discord Gateway worker and event normalization
- Discord audit-log Gateway signal + REST fallback correlation
- SQLAlchemy 2.x async PostgreSQL/Supabase integration
- Alembic migration baseline
- Guild/security configuration persistence
- Idempotent guild auto-setup
- APXOR security resources and protected-resource tracking
- Permission auditing and configurable critical-permission enforcement
- Owner-aware, guild-scoped capability authorization with expiry support
- Authorized channel, role, and moderation command foundations
- Deterministic event fingerprinting, duplicate suppression, and velocity correlation
- Privilege-escalation scoring, including emergency `ADMINISTRATOR` detection
- Deterministic decision kernel and protection state machine
- Emergency lockdown lifecycle
- Incident aggregation and severity escalation
- Versioned Discord snapshots
- Priority-aware, dependency-aware, rate-limit-aware recovery
- Durable multi-target recovery accounting and verification lifecycle
- Owner DM / protected-channel alert escalation
- Advisory Groq threat analysis with strict structured output
- AI audit persistence, hashing, asynchronous execution, and failure isolation
- Read-only `/ai status` and `/ai incident`
- Dashboard security API
- Discord OAuth2 dashboard login/session flow with signed server-side sessions
- Guild-scoped dashboard authorization
- API-key compatibility for internal service-to-service callers
- Security-focused unit and end-to-end decision-pipeline tests
- Docker image and GitHub Actions CI/test workflows

## Remaining engineering work

### P0 — finish backend security MVP

1. Expand command coverage for snapshot/recovery/configuration management.
2. Add role-member assignment restoration and stronger post-recovery verification.
3. Harden reconciliation for eventually-consistent Discord resource/audit-log cases.
4. Add full Discord integration tests and controlled attack simulations.
5. Add chaos tests for Gateway reconnects, duplicate/missing events, database outages, Groq outages, and Discord 429s.
6. Add production observability: structured security metrics, health/readiness checks, error tracking, and alerting.

### P1 — dashboard

1. Build the browser frontend against the authenticated dashboard API.
2. Add login/logout/session handling in the frontend without exposing `DASHBOARD_API_KEY`.
3. Implement Overview, Security Center, Incidents, Events, Recovery, Snapshots, AI, Operators, and Settings views.
4. Add dashboard action confirmations and owner-only controls.

### P2 — production deployment

1. Separate API and Discord worker processes/services.
2. Add external queue/worker processing for non-critical asynchronous work.
3. Configure Supabase production database and migrations.
4. Configure Render health checks and deployment verification.
5. Perform controlled staging-server attack/recovery tests before production use.

## Security invariants

- Deterministic policy is the root of trust; AI is advisory only.
- No AI output can directly execute a Discord mutation.
- Owner authority is derived from the current Discord guild owner.
- APXOR does not claim to intercept Discord REST requests before they execute.
- Recovery reconstructs server state; deleted Discord IDs and message history are not resurrected.
- If Groq is unavailable, deterministic detection, containment, notifications, and recovery continue.
- If a recovery batch has any failed target, the incident remains open and the protection state does not falsely return to `PROTECTED`.

## Next milestone

**P0 backend hardening → P1 dashboard frontend.**

The next coding pass should prioritize recovery completeness and Discord integration/chaos testing before adding non-essential product features.
