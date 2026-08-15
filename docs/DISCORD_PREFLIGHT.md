# Read-only Discord production preflight

APEXOR must pass this preflight before any destructive recovery/containment test is run against a real Discord guild.

## What it checks

The preflight is intentionally read-only. It does not create, delete, edit, or reorder Discord resources.

For each visible guild it checks:

- APEXOR can resolve its bot member.
- `VIEW_AUDIT_LOG` is available.
- `MANAGE_ROLES` is available.
- `MANAGE_CHANNELS` is available.
- `MANAGE_WEBHOOKS` is available.
- The APEXOR top role is not `@everyone`.
- Non-managed roles do not carry APEXOR's protected destructive permissions.
- The current bot role hierarchy is visible before testing containment/recovery.

## Run locally

```powershell
python -m scripts.discord_preflight
```

Inspect one guild only:

```powershell
python -m scripts.discord_preflight --guild <GUILD_ID>
```

The command uses the same `DISCORD_TOKEN` configured for APEXOR. Do not put the token on the command line.

## Result policy

`PASS` means the guild is suitable for the next controlled test stage. It does **not** mean the bot is 100% protected.

`FAIL` means stop. Do not run destructive testing until the reported permission/hierarchy issue is resolved and the preflight passes again.

This preflight is deliberately separate from the long-running worker so a production security process cannot accidentally turn a validation step into a mutating operation.
