# APXOR v1 — Chaos & Resilience Test Plan

This document defines the failure-mode and adversarial test contract for APXOR v1.

## 1. Deterministic security scenarios

| Scenario | Expected result |
|---|---|
| 1 channel deletion | Event recorded; baseline risk applied |
| 5 rapid channel deletions | Elevated velocity risk; lockdown eligible |
| 20 rapid channel deletions | High-risk/lockdown path; recovery eligible |
| Mass role deletion | High-risk/lockdown path |
| `ADMINISTRATOR` grant | Critical/emergency risk; lockdown path |
| Protected resource deletion | Immediate elevated risk |
| Mixed destructive actions | Mixed-attack bonus applied |
| Duplicate Gateway event | No duplicate velocity contribution |
| Same audit-log entry with multiple Gateway signals | Idempotently correlated |
| Old events outside correlation window | Do not affect current velocity |
| Event burst above configured buffer | Correlator remains bounded |

## 2. Failure isolation

APXOR security enforcement must continue to operate when non-critical dependencies fail.

- Groq unavailable → deterministic rules remain authoritative.
- Database temporarily unavailable → runtime decision must not depend on a successful persistence write.
- Discord rate limit → recovery/notification work must respect retry/backoff boundaries.
- Gateway reconnect → event processing resumes without resetting security policy incorrectly.
- Duplicate delivery → idempotency prevents duplicate enforcement/recovery.
- Missing event → periodic reconciliation must remain the secondary consistency mechanism.

## 3. Recovery validation

Recovery tests must verify:

1. Snapshot exists before destructive activity.
2. Recovery chooses protected resources first.
3. Recovery actions are idempotent.
4. Partial failure is persisted as an incident state rather than silently marked successful.
5. Post-recovery verification compares reconstructed state with the snapshot.
6. Rate-limit responses do not cause uncontrolled request bursts.

## 4. Production gates

APXOR v1 is not considered production-ready until:

- deterministic security tests pass;
- chaos tests pass;
- Discord integration tests pass against a dedicated test guild;
- recovery is verified for channels, roles, permission overwrites and ordering;
- database/Groq outage behavior is verified;
- Gateway reconnect and duplicate-delivery behavior is verified;
- CI executes the full test suite on every push to `main`.

## 5. Test boundary

These tests validate APXOR's own security logic and controlled test-guild behavior. They must not be executed against production Discord guilds or third-party servers without authorization.
