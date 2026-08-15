# APEXOR Implementation Status

Updated after the production-preflight milestone on `main`.

## Overall estimate

- **Backend security MVP:** ~92%
- **Complete product:** ~70%

These are engineering estimates, not a production-readiness certification. The percentages are intentionally unchanged until live Discord integration and deployment verification are completed.

## Completed core

- FastAPI API foundation and liveness/readiness/deep-health endpoints
- Async SQLAlchemy/PostgreSQL with Supabase-compatible configuration
- Alembic migrations through revision `0011`
- Discord Gateway monitoring
- Real-time audit-log correlation with REST fallback
- Event normalization and duplicate suppression
- Deterministic velocity/risk scoring
- Privilege-escalation detection
- Protected-resource detection
- Permission auditing and automatic critical-permission enforcement
- Idempotent guild auto-setup
- Capability-based authorization
- Security/channel/role/moderation slash-command foundations
- Explicit `/recovery` command surface
- Versioned guild/channel/role snapshots
- Priority/rate-limit-aware recovery worker
- Recovery verification for reconstructed roles/channels
- Role-member assignment restoration in recovery
- Incident aggregation and owner escalation
- Deterministic lockdown state machine
- Advisory Groq threat analysis with structured persistence
- Dashboard OAuth/session foundation with CSRF protection
- Dashboard security API and Vite frontend foundation
- Render web/worker topology configuration
- Docker and GitHub Actions CI/test/security workflows
- Read-only Discord permission preflight
- Non-destructive production environment preflight

## Latest milestone

### Production environment preflight

Added `scripts/production_preflight.py` and unit coverage in `tests/test_production_preflight.py`.

The check validates, without printing secrets:

- `APP_ENV=production`
- required Discord, PostgreSQL and dashboard authentication variables
- minimum dashboard session-secret strength
- HTTPS/public Discord OAuth callback URL
- HTTPS/public dashboard URL
- PostgreSQL database URL scheme
- optional Groq configuration without making AI a security-core dependency

Run locally before a Render production deployment:

```powershell
python -m scripts.production_preflight
```

## Remaining major work

### P0 — Production security hardening

- Complete Discord integration tests against a disposable test guild
- Live chaos tests for Gateway reconnects, duplicate/missing events, 429s and database outages
- Verify recovery dependency mapping against real deleted parent categories and recreated roles
- Verify all recovery mutations after Discord API propagation
- Expand audit/resource reconciliation for eventually-consistent cases
- Production observability, alerting and deployment verification

### P1 — Product surface

- Production browser verification of Discord OAuth/session flow
- Complete configuration management UI/API
- Full snapshot/recovery management UI
- Conversational `/ai ask` and dedicated authorized AI channel
- Operational incident analytics and richer dashboard views

### P2 — Advanced recovery

- More Discord resource types
- Webhook/integration recovery where technically possible
- Recovery dry-run and preview mode
- Larger-scale durable queue/worker infrastructure

## Security rule

Deterministic policy remains the root of trust. Groq is advisory only and cannot directly execute Discord mutations. Recovery is state reconstruction, not resurrection of deleted Discord IDs or message history.
