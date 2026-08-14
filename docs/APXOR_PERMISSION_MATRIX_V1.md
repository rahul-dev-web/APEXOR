# APXOR Permission Matrix v1

## Principles

- Owner remains above APXOR in Discord's role hierarchy.
- APXOR should request only permissions required by enabled modules.
- Operator roles should normally have **no raw destructive Discord permissions**.
- `ADMINISTRATOR` is prohibited for non-owner roles by APXOR policy.
- Capability authorization is separate from Discord permission possession.

## Baseline APXOR bot permissions

| Discord permission | Default | Purpose |
|---|---|---|
| VIEW_CHANNEL | Required | Read visible security/log channels |
| SEND_MESSAGES | Required | Alerts and commands |
| EMBED_LINKS | Required | Security embeds |
| READ_MESSAGE_HISTORY | Required | Context in security channels |
| USE_APPLICATION_COMMANDS | Required | Slash commands |
| VIEW_AUDIT_LOG | Required | Actor/action correlation |
| MANAGE_CHANNELS | Module-dependent | Recovery/channel management |
| MANAGE_ROLES | Module-dependent | Recovery/role management |
| MANAGE_WEBHOOKS | Module-dependent | Webhook security/recovery |
| MANAGE_GUILD | Module-dependent | Guild-level security features |
| BAN_MEMBERS | Module-dependent | Moderation response only if explicitly enabled |
| KICK_MEMBERS | Module-dependent | Moderation response only if explicitly enabled |
| MODERATE_MEMBERS | Module-dependent | Timeout response only if explicitly enabled |
| ADMINISTRATOR | **Never by default** | Avoid as unnecessary root privilege |

## Operator raw permissions

| Operator function | Raw Discord destructive permission | APXOR capability |
|---|---:|---|
| Channel manager | No | CHANNEL_CREATE / EDIT / DELETE |
| Role manager | No | ROLE_CREATE / EDIT / DELETE |
| Moderator | No | MOD_KICK / BAN / TIMEOUT |
| Security operator | No | SECURITY_VIEW / SECURITY_MANAGE |
| Recovery operator | No | SNAPSHOT_VIEW / RECOVERY_MANAGE |
| AI operator | No | AI_USE / AI_MANAGE |

## Hierarchy invariant

`Owner > APXOR bot role > protected/operator roles > normal roles > @everyone`

The exact role ordering may vary by guild, but APXOR must verify that it can manage every role/resource it is expected to manage. If a protected role is above APXOR, protection status becomes degraded.

## Privileged-role audit

The audit engine classifies non-owner `ADMINISTRATOR` as `EMERGENCY`, other dangerous direct permissions as `CRITICAL/HIGH` depending on policy, and owner-controlled privilege as informational rather than an attack finding.
