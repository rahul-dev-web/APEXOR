# APEXOR Security Specification v1

**Status:** Frozen baseline for implementation  
**Scope:** Anti-nuke/security core, authorization, recovery, AI boundary

## 1. Security objective

APEXOR does not claim that Discord destructive actions are mathematically impossible. The target is to make protected destructive permissions unavailable to manageable non-owner roles by default; detect privilege escalation and destructive behavior in real time; correlate Gateway activity with Discord Audit Logs; apply deterministic containment where Discord permits it; reconstruct lost server state from snapshots; and maintain an auditable security trail.

## 2. Root-of-trust hierarchy

```text
Discord permission isolation
        ↓
Gateway + Audit Log signals
        ↓
Deterministic normalization/deduplication
        ↓
Rule + risk engine
        ↓
Policy/containment engine
        ↓
Recovery engine
        ↓
Groq advisory analysis
```

AI is never the authorization root and never receives arbitrary Discord tool access.

## 3. Permission isolation policy

Critical permissions:

- `ADMINISTRATOR`
- `MANAGE_GUILD`
- `MANAGE_CHANNELS`
- `MANAGE_ROLES`
- `MANAGE_WEBHOOKS`

When enforcement is enabled, these permissions must not be present on manageable non-owner roles. APEXOR must never rewrite `@everyone`, managed/integration roles, roles at or above APEXOR's top role, or the guild owner's top role.

## 4. APEXOR capability model

Discord permissions and APEXOR capabilities are intentionally separate.

| Capability | Purpose |
|---|---|
| `CHANNEL_CREATE` | Create channels through APEXOR |
| `CHANNEL_EDIT` | Edit channel metadata |
| `CHANNEL_DELETE` | Delete channels through APEXOR |
| `ROLE_CREATE` | Create roles through APEXOR |
| `ROLE_EDIT` | Edit role metadata |
| `ROLE_DELETE` | Delete roles through APEXOR |
| `MOD_KICK` | Kick members through APEXOR |
| `MOD_BAN` | Ban members through APEXOR |
| `MOD_TIMEOUT` | Timeout members through APEXOR |
| `SECURITY_VIEW` | Read security state |
| `SECURITY_MANAGE` | Manage protected security resources |
| `AI_USE` | Use APEXOR AI security analysis |
| `LOG_VIEW` | Read security logs |

Owner authority is always checked against the current Discord guild owner ID.

## 5. Protected resources

APEXOR treats its bot role, security roles, critical alert/log channels, security category, and security configuration as protected assets. Protected-resource modification escalates independently of ordinary event velocity.

## 6. Event monitoring matrix

| Event family | Primary signal | Security purpose |
|---|---|---|
| Channel create/update/delete | Gateway | Detect channel tampering/nuke |
| Role create/update/delete | Gateway | Detect role tampering/escalation |
| Guild update | Gateway | Detect guild-level setting changes |
| Member update/remove | Gateway + Audit Logs | Detect moderation abuse |
| Audit log entry create | Gateway | Real-time actor correlation |
| Webhook update | Gateway + Audit Logs | Detect webhook abuse |
| Integration/bot changes | Gateway + Audit Logs | Detect third-party threat changes |

Gateway signals are normalized and deduplicated. REST Audit Logs provide fallback/reconciliation where required.

## 7. Deterministic risk matrix

| Signal | Baseline |
|---|---:|
| `ADMINISTRATOR` grant | 95 / EMERGENCY |
| `MANAGE_GUILD` grant | 85 / HIGH |
| `MANAGE_CHANNELS` grant | 85 / HIGH |
| `MANAGE_ROLES` grant | 85 / HIGH |
| `MANAGE_WEBHOOKS` grant | 80 / CRITICAL |
| Protected resource modification | protected-target escalation |
| Repeated destructive actions | velocity escalation |
| Mixed destructive action families | correlation escalation |
| APEXOR resource tampering | emergency escalation |

Risk states are deterministic and versioned in code. AI must not override them.

## 8. Lockdown state machine

```text
INITIALIZING → PROTECTED
PROTECTED → SUSPICIOUS → HIGH_RISK → LOCKDOWN
LOCKDOWN → RECOVERING → PROTECTED
RECOVERY_FAILED → RECOVERING
RECOVERY_FAILED → LOCKDOWN
DISABLED → INITIALIZING
```

A benign event must not silently downgrade an active `LOCKDOWN` state.

## 9. Incident model

Individual events are grouped into incidents by guild, actor, attack family, and a short correlation window. Severity may escalate but must not be reduced merely because later events are benign.

## 10. Recovery contract

Recovery is **state reconstruction**, not perfect resurrection. Snapshots can restore channel/category structure, channel metadata, permission overwrites, role metadata, and selected protected configuration. They cannot guarantee deleted Discord IDs, deleted message history, or non-recreatable Discord metadata.

Recovery must be idempotent, dependency-aware, priority-aware, rate-limit-aware, and verified after mutation.

Priority:

1. APEXOR security resources
2. Protected resources
3. Structural dependencies/categories
4. Ordinary resources

## 11. AI boundary

Groq receives normalized security context only. Its output is schema-constrained and advisory. The policy engine decides which action is allowed; AI cannot execute arbitrary Discord mutations.

If Groq is unavailable, deterministic detection, containment, notification, persistence, and recovery continue.

## 12. Failure-mode requirements

### Gateway reconnect

Reconnect safely, reconcile missed/duplicated state, and avoid duplicate security actions.

### Database outage

Keep deterministic in-memory security processing alive where possible, buffer/retry persistence, and do not disable protection because persistence is degraded.

### Groq outage

Mark AI degraded and continue deterministic security operations.

### Discord 429

Respect Discord rate-limit responses, queue recovery work, and never retry in a tight loop.

### Duplicate/missing events

Use stable fingerprints/audit IDs for idempotency and periodically reconcile server state.

## 13. Security status contract

`FULLY PROTECTED` should only be exposed when the current owner is identified, APEXOR is connected, required permissions are available, role hierarchy is valid, critical permission policy is healthy, security resources are protected, monitoring is active, persistence is healthy, and snapshot/recovery is healthy.

Otherwise expose `DEGRADED`, `VULNERABLE`, or `LOCKDOWN` as appropriate.

## 14. Implementation priority

### P0 — security correctness

- permission isolation
- event normalization/deduplication
- actor correlation
- deterministic risk/lockdown
- protected-resource enforcement
- idempotent recovery

### P1 — operational completeness

- reconciliation hardening
- recovery verification
- complete command coverage
- production queue/worker separation
- observability

### P2 — product surface

- dashboard OAuth/session authentication
- dashboard frontend
- conversational `/ai ask`
- dedicated AI channel

### P3 — resilience validation

- Discord integration tests
- chaos testing
- deployment verification

## 15. Non-negotiable rules

1. AI is advisory, never the security root of trust.
2. No manageable non-owner role should retain critical destructive permissions under enforcement.
3. Owner identity is derived from Discord, not trusted solely from stored configuration.
4. Gateway + Audit Logs are both part of detection.
5. Security mutations are idempotent.
6. Recovery is rate-limit-aware.
7. Security must degrade gracefully when AI is unavailable.
8. APEXOR must not claim 100% protection.
9. Browser clients must never receive the dashboard service secret.
10. Every future security feature must preserve this boundary model.
