# APEXOR Security Specification v1

## 1. Security objective

APEXOR is a security-first Discord anti-nuke platform. Its objective is to make unauthorized destructive operations unavailable by default, detect privilege escalation and destructive behavior in real time, contain incidents where Discord permits, reconstruct recoverable server state, and maintain an auditable security trail.

APEXOR does **not** claim that Discord actions can be intercepted before execution or that deleted Discord state can always be perfectly resurrected.

## 2. Security hierarchy

The security model is intentionally layered:

1. Discord permission isolation — primary prevention boundary.
2. Gateway event monitoring — real-time detection.
3. Audit-log correlation — actor attribution and authoritative administrative context.
4. Deterministic risk/correlation engine — velocity, privilege and protected-resource scoring.
5. Deterministic decision kernel — enforcement policy; AI is not a root of trust.
6. Containment/lockdown — emergency protection state.
7. Snapshot-based recovery — state reconstruction after destructive changes.
8. Groq advisory analysis — contextual classification and explanation only.
9. Dashboard and audit history — operator visibility.

## 3. Non-negotiable rules

- AI must never authorize arbitrary Discord mutations.
- Security enforcement must remain operational when Groq is unavailable.
- Non-owner manageable roles should not receive `ADMINISTRATOR` or other protected destructive permissions by default.
- APEXOR must never rewrite `@everyone`, managed/integration roles, roles above its hierarchy position, or the guild owner.
- Operator capabilities are APEXOR capabilities, not a reason to grant broad Discord permissions.
- Security actions must be idempotent.
- Gateway signals and REST reconciliation must tolerate duplicate, missing, delayed and eventually-consistent events.
- Recovery means state reconstruction, not resurrection of deleted Discord IDs or message history.
- Protection status must represent actual system health; APEXOR must not claim 100% protection.

## 4. Protected permission policy

The default critical policy treats these as protected on manageable non-owner roles:

- `ADMINISTRATOR`
- `MANAGE_GUILD`
- `MANAGE_CHANNELS`
- `MANAGE_ROLES`
- `MANAGE_WEBHOOKS`

`ADMINISTRATOR` is emergency severity because it bypasses channel permission overwrites and grants broad authority.

Permission enforcement is conservative: it must respect Discord role hierarchy and managed-role constraints. The owner remains the ultimate Discord authority and cannot be controlled by APEXOR.

## 5. Detection signals

Primary resource and security signals include:

- Channel create/update/delete.
- Role create/update/delete.
- Guild updates.
- Member moderation/removal events.
- Real-time audit-log entries.
- Webhook changes.
- Integration/bot changes.
- Privilege changes and permission diffs.
- APEXOR protected-resource modifications.

The event layer normalizes these into a stable internal security-event representation.

## 6. Risk model

Risk is deterministic. Examples of baseline signals:

| Signal | Baseline |
|---|---:|
| `ADMINISTRATOR` grant | 95 / EMERGENCY |
| `MANAGE_GUILD`, `MANAGE_CHANNELS`, `MANAGE_ROLES` grant | 85 / HIGH |
| `MANAGE_WEBHOOKS` grant | 80 / CRITICAL |
| Rapid destructive activity | velocity-based |
| Protected-resource modification | protected-target escalation |

Velocity, actor history, target importance, privilege escalation and mixed destructive activity may increase the resulting score.

Risk bands:

- 0–19 SAFE
- 20–39 LOW
- 40–59 MEDIUM
- 60–79 HIGH
- 80–94 CRITICAL
- 95–100 EMERGENCY

## 7. Decision boundary

The decision pipeline is:

```text
Gateway / Audit signal
        -> normalize
        -> correlate
        -> deterministic risk
        -> decision kernel
        -> protection runtime
        -> lockdown / recovery / notification
        -> asynchronous AI advisory analysis
```

Groq receives normalized security context and returns schema-constrained advisory output. Its recommendation is persisted for auditability but cannot directly execute a Discord operation.

## 8. Protection lifecycle

```text
INITIALIZING -> PROTECTED
PROTECTED -> SUSPICIOUS -> HIGH_RISK -> LOCKDOWN
HIGH_RISK / LOCKDOWN -> RECOVERING
RECOVERING -> PROTECTED | DEGRADED | RECOVERY_FAILED
RECOVERY_FAILED -> RECOVERING | LOCKDOWN | DEGRADED
```

A low-risk event must not silently clear an active `LOCKDOWN`, `RECOVERING`, or `RECOVERY_FAILED` state.

## 9. Incident model

Individual security events are grouped into incidents by guild, actor and attack family over a short correlation window. Incident severity escalates deterministically.

Critical incidents should produce immediate owner escalation and protected-channel alerts. Normal events remain auditable without creating notification floods.

## 10. Recovery model

Snapshots should cover recoverable Discord state such as:

- Guild security configuration.
- Channels and categories.
- Roles and permission overwrites.
- Protected resources.
- Role memberships where supported.
- Webhook metadata where supported.

Recovery is priority-aware, dependency-aware, idempotent and rate-limit-aware. Protected APEXOR resources have higher priority. Multi-resource recovery remains open until the complete expected target set is verified; one successful restoration must not prematurely resolve an incident.

## 11. Availability and failure isolation

The security core must continue deterministic enforcement if:

- Groq is unavailable.
- Database access is temporarily degraded.
- Discord emits duplicate signals.
- Audit-log correlation is delayed.
- Discord REST returns rate limits.
- The Gateway reconnects.

Production architecture may separate API and worker processes, but security decisions must not depend on a single AI or dashboard component.

## 12. Dashboard security boundary

Browser users authenticate through Discord OAuth. Server-side authorization verifies the authenticated principal has owner, `ADMINISTRATOR`, or `MANAGE_GUILD` access to the selected guild. The internal dashboard service-key path is retained only for trusted server-to-server use and must never be exposed to browser clients.

Any future dashboard mutation endpoint must enforce server-side authorization and add an explicit CSRF/session mutation policy before production use.

## 13. Production-readiness gates

APEXOR is not production-ready until the following are verified:

- Full Discord integration tests.
- Gateway reconnect and duplicate/missing event tests.
- Discord 429/rate-limit recovery tests.
- Database outage and reconnection tests.
- Recovery failure and partial-recovery tests.
- Permission hierarchy edge cases.
- Third-party bot/integration threat scenarios.
- Dashboard OAuth/session security verification.
- Production observability and alerting.
- Render deployment and health-check verification.
- No secrets committed to the repository.

## 14. Success criterion

The system is successful when unauthorized destructive actions are prevented whenever the Discord permission model allows prevention; otherwise the action is detected, attributed, contained, reconstructed where technically possible, and recorded with enough evidence for an operator to understand what happened.
