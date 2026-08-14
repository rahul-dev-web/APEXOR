# APXOR Security Specification v1

## 1. Security objective

APXOR is a Discord security platform whose primary objective is to make unauthorized destructive operations unavailable by default, then detect, contain, reconstruct, and audit destructive activity that still occurs.

APXOR does **not** claim that Discord nukes can be made mathematically impossible. Discord does not expose a pre-request interception/firewall layer for arbitrary user or bot REST requests.

## 2. Security hierarchy

1. Discord permission isolation
2. Real-time Gateway detection
3. Audit-log actor correlation
4. Deterministic risk scoring
5. Policy-controlled containment
6. Snapshot/state reconstruction
7. AI contextual analysis
8. Dashboard/analytics

AI is never the root of trust and never directly receives unrestricted Discord execution authority.

## 3. Trust boundaries

### Discord
Source of truth for guild ownership, roles, permissions, channels, members, audit records, and executable Discord actions.

### APXOR security core
Deterministic policy, event normalization, correlation, risk scoring, authorization, containment, and recovery orchestration.

### PostgreSQL/Supabase
Durable security memory: configuration, capabilities, events, incidents, snapshots, and recovery history. Database availability must not be required for the first emergency decision.

### Groq
Advisory threat analysis only. Structured output may classify or explain an incident, but a deterministic APXOR policy engine decides whether any action is permitted.

## 4. Owner policy

- Discord guild owner is the ultimate Discord authority.
- Owner identity must be refreshed from Discord, not trusted solely from a cached database value.
- Ownership changes are security events.
- APXOR must not claim that it can override the owner or a role above the bot's highest role.
- `ADMINISTRATOR` for non-owner roles is an emergency-level finding by default.

## 5. Permission isolation policy

Operators receive APXOR capabilities rather than direct destructive Discord permissions whenever possible.

Capability examples:

- `CHANNEL_CREATE`, `CHANNEL_EDIT`, `CHANNEL_DELETE`
- `ROLE_CREATE`, `ROLE_EDIT`, `ROLE_DELETE`
- `MOD_KICK`, `MOD_BAN`, `MOD_TIMEOUT`
- `SECURITY_VIEW`, `SECURITY_MANAGE`
- `LOG_VIEW`, `INCIDENT_VIEW`, `INCIDENT_MANAGE`
- `SNAPSHOT_VIEW`, `SNAPSHOT_CREATE`, `RECOVERY_MANAGE`
- `CONFIG_VIEW`, `CONFIG_MANAGE`
- `AI_USE`, `AI_MANAGE`

An APXOR capability does not imply the corresponding raw Discord permission.

## 6. Protection states

`INITIALIZING -> PROTECTED -> SUSPICIOUS -> HIGH_RISK -> LOCKDOWN -> RECOVERING -> PROTECTED`

Failure path:

`RECOVERING -> RECOVERY_FAILED`

Operational health may independently become `DEGRADED` without implying an attack.

## 7. Risk thresholds

| Score | State | Default response |
|---:|---|---|
| 0-19 | SAFE | Log when useful |
| 20-39 | LOW | Log |
| 40-59 | MEDIUM | Log + contextual monitoring |
| 60-79 | HIGH | Alert + containment evaluation |
| 80-94 | CRITICAL | Immediate incident + owner alert + containment |
| 95-100 | EMERGENCY | Lockdown policy + owner escalation + recovery |

Scores are deterministic and capped at 100.

## 8. Protected resources

APXOR security roles, security channels, configured protected roles/channels/categories, and security configuration are first-class protected resources.

A destructive action against a protected resource receives a major risk uplift and must never be silently treated as ordinary activity.

## 9. Event sources

APXOR uses both:

- Discord Gateway lifecycle events for low-latency signals.
- Discord audit-log data for actor attribution and authoritative administrative action context.

Event processing must be idempotent. Audit-log IDs or explicit event IDs are preferred for deduplication.

## 10. Detection rules

High-priority patterns include:

- Rapid channel deletion
- Rapid role deletion
- Rapid channel/role creation
- Privilege escalation
- Non-owner `ADMINISTRATOR` grants
- APXOR security role modification/deletion
- Protected channel modification/deletion
- Webhook changes
- Integration changes
- Mass member removal/moderation activity
- Guild security setting tampering

Velocity is evaluated over a short rolling window and must be correlated by actor whenever the actor is available.

## 11. Containment boundary

Containment may include APXOR-mediated command suspension, alerting, recovery queueing, and permitted Discord changes. APXOR cannot cancel an arbitrary REST request already executing elsewhere and cannot modify roles above its highest role.

Therefore the strongest prevention control remains permission isolation.

## 12. Snapshot and recovery contract

Snapshots capture reconstructable Discord state, including channel hierarchy, role configuration, permission overwrites, and other explicitly supported metadata.

Recovery means **state reconstruction**, not perfect resurrection. Deleted Discord channel IDs, message history, and Discord-generated metadata cannot be assumed recoverable.

Recovery must be:

- idempotent
- priority-aware
- rate-limit aware
- verifiable after execution
- persisted as an auditable recovery action

## 13. AI contract

Groq receives normalized incident context and returns a constrained structured analysis such as classification, confidence, explanation, and recommended policy action.

The APXOR policy engine remains the only component allowed to translate that recommendation into an executable security action.

If Groq is unavailable, deterministic security, logging, snapshot, and recovery systems continue operating.

## 14. Failure-mode requirements

- Database outage: security decisions continue from in-memory state; events are buffered where practical.
- AI outage: security core remains fully operational.
- Discord 429: recovery queues honor retry/rate-limit information.
- Gateway reconnect: state reconciliation repairs missed/inconsistent local state.
- Duplicate events: deduplicated safely.
- Missed events: periodic reconciliation provides eventual correction.
- Process restart: durable configuration and snapshots are reloaded.

## 15. Protection status contract

APXOR may show `FULLY PROTECTED` only when the minimum security invariants are healthy: owner identified, required Discord permissions present, bot role hierarchy valid, event monitoring active, database reachable or explicitly operating in emergency mode, snapshots healthy, and no known unauthorized privileged-role condition.

Otherwise the UI must report a degraded/vulnerable state rather than claiming full protection.
