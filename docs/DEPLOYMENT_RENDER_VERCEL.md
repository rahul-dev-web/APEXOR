# APEXOR Production Deployment — Render + Supabase + Vercel

This is the fastest supported production path for the current APEXOR v1 repository.

## 1. Supabase / PostgreSQL

Create a PostgreSQL database in Supabase and copy a connection string using the PostgreSQL URI form:

```text
postgresql://USER:PASSWORD@HOST:PORT/DATABASE?sslmode=require
```

For migrations, prefer a direct/session PostgreSQL connection rather than a transaction-pooler URL when possible.

APEXOR's Alembic environment normalizes plain `postgresql://` and `postgres://` URLs to SQLAlchemy's async `postgresql+psycopg://` dialect.

## 2. Discord application

Create a Discord application and bot, then enable these bot permissions for the initial APEXOR security baseline:

- View Channels
- Send Messages
- Embed Links
- Read Message History
- View Audit Log
- Manage Channels
- Manage Roles
- Manage Webhooks

Do **not** give APEXOR `Administrator` unless there is a specific operational reason. Put the APEXOR bot role above the roles it must audit/enforce/recover and below the server owner.

Dashboard OAuth scopes are:

```text
identify guilds
```

The production OAuth callback must exactly match the configured `DISCORD_REDIRECT_URI`.

## 3. Render

Create a Render Blueprint from the repository root using `render.yaml`.

The blueprint creates:

- `apexor-api` — Docker web service
- `apexor-worker` — Docker background worker

The API service runs:

```text
alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

The worker waits until the database reports the current Alembic head and then starts the Discord Gateway worker. This avoids a cold-deploy race between the web migration and worker startup.

Set these environment variables in both Render services:

```text
DISCORD_TOKEN
DATABASE_URL
GROQ_API_KEY              # optional; AI becomes degraded when absent
GROQ_MODEL
DASHBOARD_API_KEY         # server-side only
DISCORD_CLIENT_ID
DISCORD_CLIENT_SECRET
DISCORD_REDIRECT_URI
DASHBOARD_FRONTEND_URL
DASHBOARD_SESSION_SECRET  # >= 32 random characters
```

`APP_ENV` is already set to `production` by `render.yaml`.

Use:

```text
https://<your-api>.onrender.com/health
https://<your-api>.onrender.com/health/ready
https://<your-api>.onrender.com/health/deep
```

for liveness/readiness/dependency checks.

## 4. Vercel dashboard

Create a Vercel project from this GitHub repository and set the project root directory to:

```text
dashboard
```

Build command:

```text
npm run build
```

Output directory:

```text
dist
```

Production environment variable:

```text
VITE_APEXOR_API_URL=https://<your-api>.onrender.com
```

The dashboard uses Discord OAuth and HttpOnly session cookies. Do not put `DASHBOARD_API_KEY`, `DISCORD_CLIENT_SECRET`, or `DASHBOARD_SESSION_SECRET` in Vercel.

After the Vercel URL is known, set Render:

```text
DASHBOARD_FRONTEND_URL=https://<your-dashboard>.vercel.app
```

Then set the Discord OAuth redirect URI to:

```text
https://<your-api>.onrender.com/api/dashboard/auth/callback
```

## 5. Production preflight

Before declaring the deployment protected, run locally with the production environment loaded:

```bash
python -m scripts.production_preflight
python -m scripts.discord_production_preflight
```

The second command is read-only and checks the live Discord bot permission/hierarchy baseline.

## 6. First live verification

After Render is healthy:

1. Invite APEXOR to a test Discord server.
2. Confirm `/health/ready` is HTTP 200.
3. Confirm the worker reaches Discord `on_ready`.
4. Confirm APEXOR creates its security resources.
5. Open the Vercel dashboard and complete Discord OAuth.
6. Verify the server appears only for an owner/admin/manage-guild operator.
7. Verify protection state is `PROTECTED`.
8. Verify the permission audit reports no manageable role with protected permissions.
9. Test one harmless role/channel update and confirm it is logged.
10. Only after this, run controlled anti-nuke/recovery tests in a disposable server.

## 7. Important security boundary

APEXOR cannot intercept another application's Discord REST request before Discord executes it. Prevention therefore depends on permission isolation. Detection, lockdown and recovery are the second line of defense for privileged or compromised actors.

APEXOR must never claim that Discord destructive actions are mathematically impossible or that deleted Discord IDs/message history can be perfectly resurrected.
