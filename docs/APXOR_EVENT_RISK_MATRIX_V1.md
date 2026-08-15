# APEXOR Event & Risk Matrix v1

## Deterministic baseline

| Event | Baseline | Protected target uplift | High-velocity trigger |
|---|---:|---:|---|
| CHANNEL_CREATE | 5 | +40 | 5 / 10 sec => +15; 10 => +30 |
| CHANNEL_UPDATE | 5 | +40 | Context-dependent |
| CHANNEL_DELETE | 25 | +40 | 3 => +20; 5 => +40; 10 => +60 |
| ROLE_CREATE | 10 | +40 | 5 => +15; 10 => +30 |
| ROLE_UPDATE | 20 | +40 | 5 => +25 |
| ROLE_DELETE | 30 | +40 | 3 => +20; 5 => +40; 10 => +60 |
| GUILD_UPDATE | 20 | +40 | 5 => +25 |
| MEMBER_UPDATE | 10 | +40 | Context-dependent |
| MEMBER_REMOVE | 15 | +40 | Context-dependent |
| WEBHOOK_UPDATE | 20 | +40 | Context-dependent |
| INTEGRATION_UPDATE | 30 | +40 | Context-dependent |

All final scores are capped at 100.

## Emergency security signals

These should be treated as emergency/critical policy candidates independent of AI:

- Non-owner `ADMINISTRATOR` grant
- APEXOR bot/security role modification or deletion
- Protected security channel deletion
- Repeated destructive operations crossing emergency thresholds
- Unauthorized privilege escalation immediately followed by destructive activity

## Correlation dimensions

Each event should be correlated using:

- guild ID
- actor ID when known
- event type
- target ID
- audit-log ID when available
- timestamp/window
- protected-resource status
- recent actor history
- current protection state

## Detection states

`SAFE -> LOW -> MEDIUM -> HIGH -> CRITICAL -> EMERGENCY`

The security state machine may promote a guild to `LOCKDOWN` when policy permits. AI can add context but cannot lower a deterministic emergency signal by itself.

## False-positive controls

- Owner actions are not automatically treated as attacks.
- Single ordinary edits remain low-risk.
- Velocity is actor-specific whenever actor attribution exists.
- Duplicate audit/Gateway observations are deduplicated.
- Protected resources receive stronger controls than ordinary resources.
- Reconciliation is used to catch missed events rather than assuming Gateway delivery is perfect.
