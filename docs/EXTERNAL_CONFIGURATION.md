# APEXOR — External Configuration & Deployment Guide

> **Purpose:** This document is the single beginner-friendly setup guide for the external services required by the current APEXOR repository.
>
> **Repository:** `https://github.com/rahul-dev-web/APEXOR`
>
> **Production architecture:** Discord + Render API + Render Worker + Supabase PostgreSQL + Groq AI + Vercel React/Vite Dashboard.

---

## 0. Read This First

APEXOR is currently split into two deployable applications inside one repository:

```text
APEXOR repository
│
├── Python backend / Discord security worker
│   ├── FastAPI API
│   ├── Discord Gateway worker
│   ├── Security engine
│   ├── Recovery engine
│   ├── Groq advisory AI
│   └── SQLAlchemy + Alembic
│
└── dashboard/
    ├── React
    ├── Vite
    └── Vercel deployment
```

The intended production deployment is:

```text
                         ┌──────────────────────┐
                         │       Discord        │
                         │ Bot + OAuth2         │
                         └──────────┬───────────┘
                                    │
                           Gateway / REST / OAuth
                                    │
                                    ▼
┌──────────────────────┐    ┌──────────────────────┐
│      Vercel          │───▶│       Render         │
│ React/Vite Dashboard │    │ FastAPI API           │
└──────────────────────┘    └──────────┬───────────┘
                                       │
                              ┌────────┴────────┐
                              ▼                 ▼
                     ┌──────────────┐   ┌──────────────┐
                     │   Supabase   │   │     Groq     │
                     │ PostgreSQL   │   │ Advisory AI  │
                     └──────────────┘   └──────────────┘
                                       
                         Render Worker
                              │
                              ▼
                       Discord Gateway
```

### Important

The current repository already contains:

- `render.yaml` with an API web service and a Discord worker.
- Dockerfile for the Python application.
- Alembic migrations.
- React/Vite dashboard under `dashboard/`.
- `dashboard/vercel.json` for SPA routing.
- `.env.example` and `dashboard/.env.example`.
- Production health endpoints.
- Discord production preflight scripts.

Therefore, **do not manually invent a different deployment architecture** unless the code is intentionally changed first.

---

# 1. External Services Required

| Service | Required? | Used for | Secret/API data needed |
|---|---:|---|---|
| GitHub | Yes | Source repository and automatic deployment source | GitHub account access only |
| Discord Developer Portal | Yes | Discord bot, bot token, OAuth2 | Bot token, Client ID, Client Secret |
| Supabase | Yes | PostgreSQL database | PostgreSQL connection URI |
| Render | Yes | FastAPI API + Discord worker | Environment variables |
| Vercel | Yes | React/Vite dashboard | `VITE_APEXOR_API_URL` only |
| Groq | Optional | Advisory threat analysis and AI features | `GROQ_API_KEY` |
| Redis | No, current version | Not required by current repository | None |
| S3/Cloudinary | No, current version | Not used by current repository | None |
| Firebase | No, current version | Not used by current repository | None |

**Important:** APEXOR currently talks to Supabase through PostgreSQL/SQLAlchemy. It does **not** require the Supabase JavaScript client or a browser-side Supabase key for the dashboard.

---

# 2. Accounts You Need Before Starting

Create/login to these accounts:

1. GitHub — repository owner/access.
2. Discord Developer Portal — bot application.
3. Supabase — PostgreSQL project.
4. Groq — only if AI features are required immediately.
5. Render — backend and worker deployment.
6. Vercel — dashboard deployment.

Official websites:

- GitHub: https://github.com/
- Discord Developer Portal: https://discord.com/developers/applications
- Supabase: https://supabase.com/
- Groq Console: https://console.groq.com/
- Render: https://render.com/
- Vercel: https://vercel.com/

---

# 3. External Configuration Map

Before deploying, collect these values:

```text
DISCORD_TOKEN                  = Discord Bot Token
DISCORD_CLIENT_ID              = Discord Application / OAuth2 Client ID
DISCORD_CLIENT_SECRET          = Discord OAuth2 Client Secret
DISCORD_REDIRECT_URI           = Render API OAuth callback URL

DATABASE_URL                   = Supabase PostgreSQL connection URI

GROQ_API_KEY                   = Groq API key (optional)
GROQ_MODEL                     = meta-llama/llama-4-scout-17b-16e-instruct

DASHBOARD_API_KEY              = long random server-side secret
DASHBOARD_SESSION_SECRET       = long random server-side session secret
DASHBOARD_SESSION_TTL_SECONDS  = 3600
DASHBOARD_FRONTEND_URL         = Vercel dashboard URL

APP_ENV                        = production
LOG_LEVEL                      = INFO

VITE_APEXOR_API_URL            = public Render API URL (Vercel only)
```

The backend's current configuration is defined in `app/core/config.py`, and the repository `.env.example` contains the same environment-variable contract.

---

# 4. Step 1 — GitHub Repository

Repository:

```text
https://github.com/rahul-dev-web/APEXOR
```

The default branch is currently:

```text
main
```

### Do not commit secrets

Never commit:

```text
.env
Discord bot token
Discord client secret
Groq API key
DATABASE_URL
DASHBOARD_API_KEY
DASHBOARD_SESSION_SECRET
Supabase database password
```

The repository already provides `.env.example` files specifically for configuration templates.

---

# 5. Step 2 — Discord Application Setup

This is the most important external configuration because APEXOR is a Discord security bot.

## 5.1 Open Discord Developer Portal

Go to:

```text
https://discord.com/developers/applications
```

Click:

```text
New Application
```

Application name:

```text
APEXOR
```

Create the application.

---

## 5.2 Copy Application ID

Open:

```text
General Information
```

Find:

```text
Application ID
```

Save it as:

```text
DISCORD_CLIENT_ID
```

Example:

```text
DISCORD_CLIENT_ID=123456789012345678
```

Do not confuse Application ID with the bot token.

---

## 5.3 Create/Configure the Bot

Open:

```text
Bot
```

If the bot does not exist, create it.

Then use:

```text
Reset Token / View Token
```

Copy the token once and store it securely.

This becomes:

```text
DISCORD_TOKEN=...
```

### If the token is ever exposed

Immediately reset it in the Discord Developer Portal and replace it everywhere it was configured.

A Discord bot token must be treated like a password.

---

# 6. Discord Bot Permissions for APEXOR

The repository's live production preflight defines the required baseline permissions as:

```text
VIEW_CHANNEL
SEND_MESSAGES
EMBED_LINKS
READ_MESSAGE_HISTORY
VIEW_AUDIT_LOG
MANAGE_CHANNELS
MANAGE_ROLES
MANAGE_WEBHOOKS
```

These correspond to the code in:

```text
scripts/discord_production_preflight.py
```

## 6.1 Why these permissions exist

### View Channel

APEXOR must be able to see the server resources it protects.

### Send Messages

Used for security alerts and operational responses.

### Embed Links

Used for rich security messages/embeds.

### Read Message History

Needed for normal Discord channel operations where message history access is required.

### View Audit Log

Critical for identifying who performed administrative actions.

### Manage Channels

Required for channel protection, controlled channel management and recovery.

### Manage Roles

Required for role security, permission enforcement and recovery.

### Manage Webhooks

Required for webhook security and cleanup.

---

# 7. Do NOT Give APEXOR Administrator by Default

Do not enable:

```text
Administrator
```

unless you deliberately decide to operate APEXOR with that elevated trust model.

The current repository is explicitly designed around a least-privilege security baseline.

Use the specific permissions above instead.

---

# 8. Discord Role Hierarchy

This is mandatory for APEXOR.

The bot's highest role must be above the roles it needs to audit/enforce/recover, but below the server owner.

A simplified hierarchy should look like:

```text
Server Owner
    │
    ▼
APEXOR Bot Role
    │
    ▼
Protected / manageable roles
    │
    ▼
Normal member roles
    │
    ▼
@everyone
```

### Why?

Discord does not allow the bot to manage roles that are at or above its highest role.

If you put a protected role above APEXOR, APEXOR cannot enforce or recover it.

The repository's production preflight checks exactly this type of hierarchy problem.

---

# 9. Discord OAuth2 Setup for Dashboard

The dashboard does not use the bot token for browser login.

It uses Discord OAuth2.

Open:

```text
OAuth2 → General
```

Add a redirect URL.

For production, it will be:

```text
https://YOUR-RENDER-API.onrender.com/api/dashboard/auth/callback
```

Example:

```text
https://apexor-api.onrender.com/api/dashboard/auth/callback
```

For local development:

```text
http://localhost:8000/api/dashboard/auth/callback
```

### Required OAuth scopes

APEXOR's dashboard authentication expects:

```text
identify guilds
```

The dashboard uses these to identify the logged-in Discord user and determine the guilds available to that user.

### Important

The redirect URI must match exactly.

For example, these are different:

```text
https://apexor-api.onrender.com/api/dashboard/auth/callback
https://apexor-api.onrender.com/api/dashboard/auth/callback/
```

Do not add/remove the trailing slash randomly.

---

# 10. Discord Bot Invite

After configuring the bot, use the OAuth2 URL Generator in the Discord Developer Portal.

Select scopes:

```text
bot
applications.commands
```

Then select the required bot permissions:

```text
View Channels
Send Messages
Embed Links
Read Message History
View Audit Log
Manage Channels
Manage Roles
Manage Webhooks
```

Generate the URL.

Open it in your browser and add APEXOR to your test server.

### Recommended first deployment

Use a disposable/test Discord server first.

Do not perform first-time recovery tests on a production community.

---

# 11. Discord Gateway Intents

The current APEXOR Discord client explicitly enables:

```python
intents = discord.Intents.none()
intents.guilds = True
intents.moderation = True
```

Therefore, the current implementation does not depend on privileged `MESSAGE_CONTENT` or `PRESENCE` intents.

You should not enable extra privileged intents just because they are available.

If a future code change requires a privileged intent, update both the code and the Discord Developer Portal configuration.

---

# 12. Step 3 — Supabase PostgreSQL Setup

Open:

```text
https://supabase.com/
```

Create a new project.

Choose:

```text
Organization → your organization
Project name → apexor
Database password → create a strong password
Region → choose the closest practical region to your users/backend
```

Wait until the database becomes ready.

---

# 13. Which Supabase Credential Does APEXOR Need?

APEXOR currently uses:

```text
DATABASE_URL
```

It does **not** need a Supabase `anon` key for the backend database connection.

It also does not currently require a browser-side `SUPABASE_URL` or `SUPABASE_ANON_KEY`.

The Python application connects using SQLAlchemy + psycopg to PostgreSQL.

---

# 14. Get the Supabase PostgreSQL Connection String

In Supabase, open the database connection/connect panel and select the PostgreSQL connection URI.

You want a URL conceptually like:

```text
postgresql://postgres:PASSWORD@HOST:5432/postgres?sslmode=require
```

Your actual host, username, password and port will be provided by Supabase.

### Important recommendation

For Alembic migrations, prefer a direct/session PostgreSQL connection rather than a transaction-pooler URL when the Supabase UI provides that option.

The APEXOR SQLAlchemy session normalizes:

```text
postgresql://...
```

and:

```text
postgres://...
```

to:

```text
postgresql+psycopg://...
```

automatically.

---

# 15. Supabase SQL Editor — What to Do

APEXOR already contains Alembic migrations.

Therefore the safest production flow is:

```text
Supabase PostgreSQL
        ↓
Render API starts
        ↓
alembic upgrade head
        ↓
APEXOR tables created/updated
```

**Do not manually recreate all APEXOR tables in SQL Editor before running Alembic.** Doing both can create schema conflicts.

Use SQL Editor mainly for verification and safe operational inspection.

---

# 16. Supabase SQL Editor — Connection Test

Open:

```text
Supabase → SQL Editor → New query
```

Run:

```sql
select
  current_database() as database_name,
  current_user as database_user,
  now() as server_time;
```

If this returns one row, the SQL Editor connection works.

---

# 17. Supabase SQL Editor — Check Alembic Migration

After the first Render deployment, run:

```sql
select version_num
from alembic_version;
```

The result should contain the current Alembic head used by the repository.

To inspect all migration versions stored by Alembic:

```sql
select version_num
from alembic_version;
```

APEXOR's Render web service runs:

```text
alembic upgrade head
```

before starting FastAPI.

---

# 18. Supabase SQL Editor — Check APEXOR Tables

After Render's first successful migration, run:

```sql
select table_name
from information_schema.tables
where table_schema = 'public'
  and table_name in (
    'guilds',
    'security_configs',
    'security_roles',
    'security_channels',
    'security_event_logs',
    'security_incidents',
    'user_capabilities',
    'security_snapshots',
    'recovery_actions',
    'ai_threat_assessments',
    'admin_changes'
  )
order by table_name;
```

You should see the APEXOR security tables.

The names correspond to the current SQLAlchemy models in the repository.

---

# 19. Supabase SQL Editor — Useful Row Counts

After APEXOR has been running for a while:

```sql
select 'guilds' as table_name, count(*) as rows from guilds
union all
select 'security_configs', count(*) from security_configs
union all
select 'security_roles', count(*) from security_roles
union all
select 'security_channels', count(*) from security_channels
union all
select 'security_event_logs', count(*) from security_event_logs
union all
select 'security_incidents', count(*) from security_incidents
union all
select 'user_capabilities', count(*) from user_capabilities
union all
select 'security_snapshots', count(*) from security_snapshots
union all
select 'recovery_actions', count(*) from recovery_actions
union all
select 'ai_threat_assessments', count(*) from ai_threat_assessments
union all
select 'admin_changes', count(*) from admin_changes
order by table_name;
```

This is a read-only diagnostic query.

---

# 20. Supabase Security Rules

### Never put the PostgreSQL password in the React dashboard.

The following are backend-only:

```text
DATABASE_URL
```

```text
DASHBOARD_API_KEY
```

```text
DASHBOARD_SESSION_SECRET
```

```text
DISCORD_CLIENT_SECRET
```

```text
DISCORD_TOKEN
```

```text
GROQ_API_KEY
```

Only the Vite variable below belongs in Vercel:

```text
VITE_APEXOR_API_URL
```

Vite variables beginning with `VITE_` are intentionally exposed to browser JavaScript. Therefore never store secrets in them.

---

# 21. Optional Supabase RLS Note

APEXOR's current architecture has the Python backend connecting directly to PostgreSQL through SQLAlchemy. Do not blindly enable RLS on every table and assume the application will continue to behave identically.

If RLS is introduced later, it must be designed together with the backend database role/authorization model and tested against every API/recovery path.

For the current deployment, **run the existing Alembic migrations first and do not rewrite the schema manually.**

---

# 22. Step 4 — Groq Setup

Groq is used as an **advisory AI layer**, not as the deterministic security root of trust.

Open:

```text
https://console.groq.com/
```

Create/login to your account.

Create an API key.

Copy it as:

```text
GROQ_API_KEY=...
```

Current default model configured by APEXOR:

```text
meta-llama/llama-4-scout-17b-16e-instruct
```

Therefore:

```text
GROQ_MODEL=meta-llama/llama-4-scout-17b-16e-instruct
```

### If Groq is not configured

APEXOR's deterministic security core should still operate. The repository intentionally isolates AI failure from detection, lockdown, notification and recovery.

So for a first deployment, Groq can be treated as optional if you need to get the core bot online quickly.

---

# 23. Step 5 — Generate Server Secrets

You need two application secrets:

```text
DASHBOARD_API_KEY
DASHBOARD_SESSION_SECRET
```

They must be random and long.

## Windows PowerShell

If Python is installed:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Run it twice.

First output:

```text
DASHBOARD_API_KEY
```

Second output:

```text
DASHBOARD_SESSION_SECRET
```

Do not use the same secret for both.

---

# 24. Step 6 — Render Setup

Open:

```text
https://render.com/
```

Sign in with GitHub.

Connect the GitHub repository:

```text
rahul-dev-web/APEXOR
```

The repository already contains:

```text
render.yaml
```

This file defines two Render services:

```text
apexor-api
apexor-worker
```

---

# 25. Why Render Has Two Services

### `apexor-api`

Runs:

```text
FastAPI
```

and exposes:

```text
/health
/health/ready
/health/deep
```

It also runs database migrations before starting the HTTP server.

### `apexor-worker`

Runs the Discord Gateway bot.

Its entrypoint is:

```text
python -m scripts.worker_entrypoint
```

The worker waits for the database migration to reach the current Alembic head before starting Discord operations.

This prevents the worker from racing the API migration during deployment.

---

# 26. Render Blueprint Deployment

In Render, create/deploy a Blueprint from the repository.

Select the repository:

```text
rahul-dev-web/APEXOR
```

Render should detect:

```text
render.yaml
```

and propose the services defined there.

Confirm creation of:

```text
apexor-api
apexor-worker
```

---

# 27. Render Environment Variables — API Service

Open:

```text
Render → apexor-api → Environment
```

Set:

```text
APP_ENV=production
LOG_LEVEL=INFO

DISCORD_TOKEN=YOUR_DISCORD_BOT_TOKEN

DATABASE_URL=YOUR_SUPABASE_POSTGRES_URL

GROQ_API_KEY=YOUR_GROQ_KEY
GROQ_MODEL=meta-llama/llama-4-scout-17b-16e-instruct

DASHBOARD_API_KEY=YOUR_RANDOM_SERVER_SECRET
DASHBOARD_SESSION_SECRET=YOUR_OTHER_RANDOM_SERVER_SECRET
DASHBOARD_SESSION_TTL_SECONDS=3600

DISCORD_CLIENT_ID=YOUR_DISCORD_APPLICATION_ID
DISCORD_CLIENT_SECRET=YOUR_DISCORD_OAUTH_CLIENT_SECRET
DISCORD_REDIRECT_URI=https://YOUR-API.onrender.com/api/dashboard/auth/callback

DASHBOARD_FRONTEND_URL=https://YOUR-DASHBOARD.vercel.app
```

### Optional AI configuration

If Groq is not ready yet:

```text
GROQ_API_KEY=
```

The service can operate with AI degraded, subject to the features being tested.

---

# 28. Render Environment Variables — Worker Service

Open:

```text
Render → apexor-worker → Environment
```

Set the same runtime configuration:

```text
APP_ENV=production
LOG_LEVEL=INFO

DISCORD_TOKEN=YOUR_DISCORD_BOT_TOKEN
DATABASE_URL=YOUR_SUPABASE_POSTGRES_URL

GROQ_API_KEY=YOUR_GROQ_KEY
GROQ_MODEL=meta-llama/llama-4-scout-17b-16e-instruct

DASHBOARD_API_KEY=YOUR_RANDOM_SERVER_SECRET
DASHBOARD_SESSION_SECRET=YOUR_OTHER_RANDOM_SERVER_SECRET
DASHBOARD_SESSION_TTL_SECONDS=3600

DISCORD_CLIENT_ID=YOUR_DISCORD_APPLICATION_ID
DISCORD_CLIENT_SECRET=YOUR_DISCORD_OAUTH_CLIENT_SECRET
DISCORD_REDIRECT_URI=https://YOUR-API.onrender.com/api/dashboard/auth/callback

DASHBOARD_FRONTEND_URL=https://YOUR-DASHBOARD.vercel.app
```

The `render.yaml` already declares these variables as required external secrets.

---

# 29. Render Start Commands

The API deployment uses:

```bash
alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Do not change `$PORT` to `8000` on Render.

Render provides the `$PORT` environment variable.

The Dockerfile exposes port `8000`, but the Render start command correctly binds Uvicorn to the platform-provided port.

The worker uses:

```bash
python -m scripts.worker_entrypoint
```

---

# 30. Render Health Check

The Render blueprint uses:

```text
/health/ready
```

This is the correct readiness endpoint for the API service.

You can also manually open:

```text
https://YOUR-API.onrender.com/health
```

Expected response conceptually:

```json
{
  "status": "ok",
  "service": "apexor-api",
  "environment": "production"
}
```

Then test:

```text
https://YOUR-API.onrender.com/health/ready
```

And:

```text
https://YOUR-API.onrender.com/health/deep
```

The deep endpoint reports safe operational dependency information without returning secret values.

---

# 31. Render Deployment Order

Use this order to avoid confusion:

```text
1. Create Supabase project
        ↓
2. Create Discord application/bot
        ↓
3. Create Groq key (optional)
        ↓
4. Create Render Blueprint
        ↓
5. Configure Render environment variables
        ↓
6. Deploy API
        ↓
7. Confirm /health/ready
        ↓
8. Confirm migrations in Supabase
        ↓
9. Confirm worker is online
        ↓
10. Get final Render API URL
        ↓
11. Configure Discord OAuth redirect
        ↓
12. Deploy Vercel dashboard
        ↓
13. Put Vercel URL into Render DASHBOARD_FRONTEND_URL
        ↓
14. Re-deploy/restart API
        ↓
15. Test dashboard OAuth
        ↓
16. Run Discord production preflight
```

---

# 32. Step 7 — Vercel Dashboard Setup

The dashboard is located at:

```text
dashboard/
```

It is a:

```text
React + Vite
```

application.

Open:

```text
https://vercel.com/
```

Create a new project from:

```text
rahul-dev-web/APEXOR
```

---

# 33. Vercel Root Directory

This is very important.

Set:

```text
Root Directory:
 dashboard
```

Do not deploy the repository root as the Vercel frontend.

The frontend application is inside:

```text
dashboard/
```

---

# 34. Vercel Build Configuration

Use:

```text
Framework Preset: Vite
```

Build command:

```bash
npm run build
```

Output directory:

```text
dist
```

Install command can normally remain automatic.

The repository's `dashboard/package.json` defines the build script.

---

# 35. Vercel Environment Variable

Add only:

```text
VITE_APEXOR_API_URL=https://YOUR-API.onrender.com
```

Example:

```text
VITE_APEXOR_API_URL=https://apexor-api.onrender.com
```

### Never add these to Vercel

```text
DISCORD_TOKEN
DISCORD_CLIENT_SECRET
DATABASE_URL
GROQ_API_KEY
DASHBOARD_API_KEY
DASHBOARD_SESSION_SECRET
```

Those are server-side secrets.

---

# 36. Vercel SPA Routing

The repository already contains:

```text
dashboard/vercel.json
```

with a rewrite to:

```text
/index.html
```

This is required because the dashboard is a Vite single-page application.

Do not remove the rewrite unless the frontend routing architecture changes.

---

# 37. After Vercel Deployment

Suppose Vercel gives you:

```text
https://apexor-dashboard.vercel.app
```

Go back to Render.

Set in **both** API and worker services:

```text
DASHBOARD_FRONTEND_URL=https://apexor-dashboard.vercel.app
```

The API's CORS configuration explicitly allows this configured origin and credentials.

Do not add:

```text
*
```

for credentialed browser requests.

---

# 38. Final Discord OAuth Redirect

Now you know the final Render API URL.

Set Discord Developer Portal → OAuth2 redirect URL to:

```text
https://YOUR-API.onrender.com/api/dashboard/auth/callback
```

Set the exact same value in Render:

```text
DISCORD_REDIRECT_URI=https://YOUR-API.onrender.com/api/dashboard/auth/callback
```

These two values must match exactly.

---

# 39. Dashboard Login Flow

The expected production flow is:

```text
User opens Vercel dashboard
        ↓
Continue with Discord
        ↓
Discord OAuth2
        ↓
Render API callback
        ↓
Discord identity/guild authorization
        ↓
Signed HttpOnly session cookie
        ↓
Browser returns to Vercel dashboard
        ↓
Dashboard calls Render API with credentials
        ↓
Security dashboard loads
```

The browser should never receive the Discord client secret or server-side session secret.

---

# 40. CORS Troubleshooting

If the Vercel dashboard says something like:

```text
CORS error
```

check Render:

```text
DASHBOARD_FRONTEND_URL
```

It must be exactly the Vercel origin.

Correct:

```text
https://apexor-dashboard.vercel.app
```

Incorrect:

```text
https://apexor-dashboard.vercel.app/
```

The backend strips a trailing slash internally, but keeping the environment value as a clean origin is recommended.

Also make sure you are not accidentally using an old Vercel preview URL.

---

# 41. Local Development Environment

## Python backend

From repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Copy environment template:

```powershell
Copy-Item .env.example .env
```

Configure `.env`.

Run migrations:

```powershell
alembic upgrade head
```

Run API:

```powershell
uvicorn app.main:app --reload
```

Run Discord worker in a second terminal:

```powershell
python -m app.bot.runner
```

---

# 42. Local Dashboard

Go into the dashboard directory:

```powershell
cd dashboard
```

Install dependencies:

```powershell
npm install
```

Copy environment file:

```powershell
Copy-Item .env.example .env
```

Set:

```text
VITE_APEXOR_API_URL=http://localhost:8000
```

Run:

```powershell
npm run dev
```

The Vite development server will print its local URL.

---

# 43. Local Discord OAuth Callback

If testing dashboard OAuth locally, Discord redirect URL should be:

```text
http://localhost:8000/api/dashboard/auth/callback
```

And backend `.env`:

```text
DISCORD_REDIRECT_URI=http://localhost:8000/api/dashboard/auth/callback
```

Dashboard:

```text
VITE_APEXOR_API_URL=http://localhost:8000
```

For production, replace these with Render/Vercel URLs.

---

# 44. Preflight Before Production

The repository contains dedicated production preflight scripts.

From the repository root:

```powershell
python -m scripts.production_preflight
```

Then:

```powershell
python -m scripts.discord_production_preflight
```

The Discord production preflight is intentionally read-only. It checks the live bot's cached guild state, required permissions and role hierarchy without changing Discord resources.

A successful result should report:

```text
Required bot permissions: OK
Manageable protected-permission roles: none
Hierarchy risks: none
Preflight passed
```

---

# 45. Production Verification Checklist

Complete this checklist in order.

## Infrastructure

- [ ] GitHub repository is accessible to Render and Vercel.
- [ ] Supabase project is created.
- [ ] Supabase PostgreSQL URI is copied.
- [ ] Discord application is created.
- [ ] Discord bot exists.
- [ ] Discord token is configured only in backend services.
- [ ] Groq key is configured if AI is required.
- [ ] Render Blueprint creates `apexor-api`.
- [ ] Render Blueprint creates `apexor-worker`.
- [ ] Vercel root directory is `dashboard`.

## Database

- [ ] Render API starts successfully.
- [ ] `alembic upgrade head` completes.
- [ ] `alembic_version` exists.
- [ ] APEXOR security tables exist.
- [ ] `/health/ready` returns HTTP 200.

## Discord

- [ ] Bot is online.
- [ ] Required permissions are granted.
- [ ] APEXOR role is above manageable roles.
- [ ] APEXOR is below the server owner.
- [ ] No unauthorized manageable role has critical protected permissions.
- [ ] OAuth2 scopes are configured.
- [ ] OAuth redirect URI matches exactly.

## Dashboard

- [ ] Vercel build succeeds.
- [ ] `VITE_APEXOR_API_URL` points to Render API.
- [ ] Render `DASHBOARD_FRONTEND_URL` points to Vercel.
- [ ] Dashboard opens.
- [ ] Continue with Discord works.
- [ ] Session cookie is created.
- [ ] Guild list loads.
- [ ] Security overview loads.
- [ ] Dashboard mutations work only for authorized users.

## Security

- [ ] Normal member cannot access APEXOR privileged commands.
- [ ] Capability authorization is server-side.
- [ ] Security events are stored.
- [ ] Incidents are stored.
- [ ] Snapshots are stored.
- [ ] Recovery records are stored.
- [ ] AI failures do not stop deterministic security.

---

# 46. First Test Server Procedure

Do not immediately install APEXOR on your main production Discord server.

Create a private test server.

Add:

```text
APEXOR
```

Then verify:

```text
1. Bot online
2. /health/ready = ready
3. Security resources created
4. Protection state becomes PROTECTED
5. Dashboard login works
6. Test harmless role/channel operation
7. Event appears in dashboard
8. Snapshot appears
9. Recovery test is performed only on disposable resources
```

Only after these tests pass should you move to a production community.

---

# 47. Common Error — `DATABASE_URL is not configured`

Symptoms:

```text
DATABASE_URL is not configured
```

Fix:

1. Open Render.
2. Open `apexor-api`.
3. Open Environment.
4. Add `DATABASE_URL`.
5. Paste the Supabase PostgreSQL URI.
6. Save.
7. Redeploy.

Also configure `DATABASE_URL` on:

```text
apexor-worker
```

The worker needs the database to verify migrations before starting.

---

# 48. Common Error — Alembic Migration Failure

Check Render API logs for:

```text
alembic upgrade head
```

Then verify:

```text
DATABASE_URL
```

and confirm the database is reachable.

In Supabase SQL Editor run:

```sql
select current_database(), current_user, now();
```

Then:

```sql
select version_num from alembic_version;
```

Do not manually delete APEXOR tables to fix an Alembic problem unless you understand the migration state and are intentionally rebuilding the database.

---

# 49. Common Error — Discord Bot Offline

Check:

```text
DISCORD_TOKEN
```

If Discord rejects the token:

1. Open Discord Developer Portal.
2. Open APEXOR application.
3. Open Bot.
4. Reset token.
5. Copy the new token.
6. Replace `DISCORD_TOKEN` in Render API and Worker.
7. Redeploy/restart both services.

Never paste the token into a GitHub issue, Discord channel, screenshot or public document.

---

# 50. Common Error — Bot Online but Security Is Degraded

Run:

```powershell
python -m scripts.discord_production_preflight
```

Check for:

```text
Missing bot permissions
```

or:

```text
Hierarchy risks
```

or:

```text
Manageable protected-permission roles
```

Fix the Discord permission/role hierarchy and run the preflight again.

---

# 51. Common Error — Dashboard Login Redirect Fails

Check all three values:

Discord Developer Portal:

```text
https://YOUR-API.onrender.com/api/dashboard/auth/callback
```

Render:

```text
DISCORD_REDIRECT_URI=https://YOUR-API.onrender.com/api/dashboard/auth/callback
```

Dashboard API URL:

```text
VITE_APEXOR_API_URL=https://YOUR-API.onrender.com
```

All three must point to the same deployed API.

---

# 52. Common Error — Dashboard CORS Error

Check:

```text
DASHBOARD_FRONTEND_URL
```

Example:

```text
DASHBOARD_FRONTEND_URL=https://apexor-dashboard.vercel.app
```

Do not use:

```text
DASHBOARD_FRONTEND_URL=*
```

The API uses credentialed browser requests, so an unrestricted wildcard origin is not appropriate.

---

# 53. Common Error — Vercel Build Cannot Find the App

Verify:

```text
Root Directory = dashboard
```

and:

```text
Build Command = npm run build
Output Directory = dist
```

Do not point Vercel at the repository root for the dashboard deployment.

---

# 54. Common Error — Vercel Dashboard Loads but API Calls Fail

Check:

```text
VITE_APEXOR_API_URL
```

It must be the public Render API URL.

Example:

```text
VITE_APEXOR_API_URL=https://apexor-api.onrender.com
```

After changing a Vercel environment variable, trigger a new deployment because Vite embeds `VITE_*` variables into the frontend build.

---

# 55. Common Error — Worker Keeps Waiting for Migration

The worker intentionally waits for:

```text
alembic_version
```

to reach the current migration head.

Check the API logs first.

The API must successfully run:

```text
alembic upgrade head
```

Then check Supabase:

```sql
select version_num from alembic_version;
```

If the API migration failed, fix the API/database problem first. Do not try to force the worker to ignore the migration check.

---

# 56. Environment Variable Master Table

## Backend — Render API + Worker

| Variable | Example | Secret? | Where |
|---|---|---:|---|
| `APP_ENV` | `production` | No | Render |
| `LOG_LEVEL` | `INFO` | No | Render |
| `DISCORD_TOKEN` | `MTA...` | **YES** | Render only |
| `DISCORD_CLIENT_ID` | `123...` | No | Render |
| `DISCORD_CLIENT_SECRET` | `abc...` | **YES** | Render only |
| `DISCORD_REDIRECT_URI` | `https://api.../api/dashboard/auth/callback` | No | Render |
| `DATABASE_URL` | `postgresql://...` | **YES** | Render only |
| `GROQ_API_KEY` | `gsk_...` | **YES** | Render only |
| `GROQ_MODEL` | `meta-llama/...` | No | Render |
| `DASHBOARD_API_KEY` | random secret | **YES** | Render only |
| `DASHBOARD_SESSION_SECRET` | random secret | **YES** | Render only |
| `DASHBOARD_SESSION_TTL_SECONDS` | `3600` | No | Render |
| `DASHBOARD_FRONTEND_URL` | `https://dashboard...` | No | Render |

## Frontend — Vercel

| Variable | Example | Secret? |
|---|---|---:|
| `VITE_APEXOR_API_URL` | `https://apexor-api.onrender.com` | No |

---

# 57. Final Production URLs

After deployment, write these down somewhere private/secure:

```text
Render API:
https://YOUR-API.onrender.com

API health:
https://YOUR-API.onrender.com/health

API readiness:
https://YOUR-API.onrender.com/health/ready

API deep health:
https://YOUR-API.onrender.com/health/deep

Dashboard:
https://YOUR-DASHBOARD.vercel.app

Discord OAuth callback:
https://YOUR-API.onrender.com/api/dashboard/auth/callback
```

---

# 58. Exact Final Configuration Example

This is an example only. Replace all placeholder values.

## Render API

```env
APP_ENV=production
LOG_LEVEL=INFO

DISCORD_TOKEN=YOUR_DISCORD_BOT_TOKEN
DISCORD_CLIENT_ID=123456789012345678
DISCORD_CLIENT_SECRET=YOUR_DISCORD_CLIENT_SECRET
DISCORD_REDIRECT_URI=https://apexor-api.onrender.com/api/dashboard/auth/callback

DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@YOUR_SUPABASE_HOST:5432/postgres?sslmode=require

GROQ_API_KEY=YOUR_GROQ_KEY
GROQ_MODEL=meta-llama/llama-4-scout-17b-16e-instruct

DASHBOARD_API_KEY=YOUR_RANDOM_SECRET_1
DASHBOARD_SESSION_SECRET=YOUR_RANDOM_SECRET_2
DASHBOARD_SESSION_TTL_SECONDS=3600
DASHBOARD_FRONTEND_URL=https://apexor-dashboard.vercel.app
```

## Render Worker

Use the same backend configuration.

## Vercel

```env
VITE_APEXOR_API_URL=https://apexor-api.onrender.com
```

---

# 59. Recommended Deployment Sequence — Copy This

```text
[ ] 1. Create Discord Application
[ ] 2. Create Discord Bot
[ ] 3. Copy DISCORD_TOKEN
[ ] 4. Copy DISCORD_CLIENT_ID
[ ] 5. Create Discord OAuth2 secret
[ ] 6. Configure bot permissions
[ ] 7. Configure bot role hierarchy
[ ] 8. Create Supabase project
[ ] 9. Copy PostgreSQL DATABASE_URL
[ ] 10. Run Supabase SQL connection test
[ ] 11. Create Groq key (optional)
[ ] 12. Generate DASHBOARD_API_KEY
[ ] 13. Generate DASHBOARD_SESSION_SECRET
[ ] 14. Deploy Render Blueprint
[ ] 15. Configure Render API variables
[ ] 16. Configure Render Worker variables
[ ] 17. Deploy API
[ ] 18. Check /health
[ ] 19. Check /health/ready
[ ] 20. Check /health/deep
[ ] 21. Check Alembic version in Supabase
[ ] 22. Check APEXOR tables in Supabase
[ ] 23. Check worker logs
[ ] 24. Confirm Discord bot online
[ ] 25. Configure final Discord OAuth redirect
[ ] 26. Deploy Vercel with root=dashboard
[ ] 27. Set VITE_APEXOR_API_URL
[ ] 28. Copy Vercel URL to DASHBOARD_FRONTEND_URL on Render
[ ] 29. Redeploy API/worker if required
[ ] 30. Test Discord OAuth dashboard login
[ ] 31. Run discord_production_preflight
[ ] 32. Install bot into disposable test server
[ ] 33. Verify auto setup
[ ] 34. Verify security logs
[ ] 35. Verify snapshots
[ ] 36. Verify recovery in disposable resources
[ ] 37. Only then move to production server
```

---

# 60. What Is NOT Required for the Current Project

Do not waste time setting up these services unless the codebase is changed to use them:

```text
Redis
Firebase
MongoDB
MySQL
Cloudinary
AWS S3
Supabase Storage
Supabase Edge Functions
Stripe
RabbitMQ
Kubernetes
```

The current production path is intentionally simpler:

```text
Discord
   +
Render
   +
Supabase PostgreSQL
   +
Groq (optional/advisory)
   +
Vercel
```

---

# 61. Security Rules for the Operator

1. Never commit `.env`.
2. Never expose `DISCORD_TOKEN`.
3. Never expose `DISCORD_CLIENT_SECRET`.
4. Never expose `DATABASE_URL`.
5. Never expose `GROQ_API_KEY`.
6. Never expose `DASHBOARD_API_KEY`.
7. Never expose `DASHBOARD_SESSION_SECRET`.
8. Never put backend secrets in `VITE_*` variables.
9. Do not give APEXOR `Administrator` without intentionally accepting that trust boundary.
10. Keep APEXOR's role above manageable protected roles.
11. Keep the server owner above APEXOR.
12. Test recovery on a disposable server first.
13. Treat Discord bot token rotation as an incident if the token may have leaked.
14. Do not manually edit production database tables when an Alembic migration should be used.
15. Keep Supabase database credentials server-side only.

---

# 62. Official Documentation

Use official documentation when a provider's dashboard UI changes:

- Discord Developer Portal: https://discord.com/developers/applications
- Discord Developer Documentation: https://docs.discord.com/developers/
- Discord OAuth2: https://docs.discord.com/developers/topics/oauth2
- Discord Permissions: https://docs.discord.com/developers/topics/permissions
- Discord Gateway: https://docs.discord.com/developers/events/gateway
- Discord Audit Log: https://docs.discord.com/developers/resources/audit-log
- Supabase Database: https://supabase.com/docs/guides/database
- Supabase Connect: https://supabase.com/docs/guides/database/connecting-to-postgres
- Groq API: https://console.groq.com/docs
- Render Blueprints: https://render.com/docs/blueprint-spec
- Render Health Checks: https://render.com/docs/health-checks
- Vercel: https://vercel.com/docs
- Vite: https://vite.dev/guide/
- Alembic: https://alembic.sqlalchemy.org/
- SQLAlchemy: https://docs.sqlalchemy.org/

---

# 63. APEXOR Repository Files Relevant to Deployment

The following repository files are the source of truth for the current deployment contract:

```text
.env.example
Dockerfile
render.yaml
requirements.txt
alembic.ini
migrations/
app/core/config.py
app/database/session.py
app/main.py
app/bot/client.py
app/bot/runner.py
scripts/worker_entrypoint.py
scripts/production_preflight.py
scripts/discord_production_preflight.py

dashboard/.env.example
dashboard/package.json
dashboard/vercel.json
dashboard/vite.config.js
dashboard/src/App.jsx
```

If this guide and the code ever disagree, **the code and deployment manifests are the implementation source of truth** and this document should be updated.

---

# 64. Final Go-Live Test

Before calling APEXOR production-ready, verify this exact flow:

```text
Discord test server
      ↓
APEXOR invited
      ↓
Bot online
      ↓
Required permissions OK
      ↓
Role hierarchy OK
      ↓
Auto setup completes
      ↓
Security state = PROTECTED
      ↓
Snapshot created
      ↓
Render API healthy
      ↓
Render Worker healthy
      ↓
Supabase migration head correct
      ↓
Vercel dashboard opens
      ↓
Discord OAuth login works
      ↓
Guild appears in dashboard
      ↓
Security overview loads
      ↓
Security event appears in Events
      ↓
Incident lifecycle works
      ↓
Snapshot/recovery path works
      ↓
AI works if Groq is configured
      ↓
AI failure does not stop deterministic security
      ↓
Production preflight PASS
      ↓
GO LIVE
```

---

## Final Note

APEXOR's current security model is **prevention + detection + containment + recovery**, not a claim that Discord can be turned into an absolute transactional firewall.

The most important external configuration is therefore not just getting the bot online. It is getting the Discord permissions and role hierarchy correct.

A correctly deployed APEXOR should have:

```text
Discord permissions      ✓
Role hierarchy           ✓
Gateway monitoring       ✓
Audit correlation        ✓
Database                  ✓
Snapshots                 ✓
Recovery                  ✓
Render API                ✓
Render Worker             ✓
Dashboard OAuth           ✓
Vercel frontend           ✓
Groq advisory AI          ✓ / DEGRADED
Health checks             ✓
Production preflight      ✓
```

Only after all required checks pass should the protection state be considered production-ready.
