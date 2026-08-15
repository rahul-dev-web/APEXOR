# APXOR Dashboard Authentication

The dashboard now supports Discord OAuth2 for browser sessions while retaining the server-to-server `DASHBOARD_API_KEY` path for internal tooling.

## OAuth configuration

Create a Discord OAuth2 application and configure:

```env
DISCORD_CLIENT_ID=
DISCORD_CLIENT_SECRET=
DISCORD_REDIRECT_URI=https://<api-host>/api/dashboard/auth/callback
DASHBOARD_SESSION_SECRET=<random secret, 32+ characters>
DASHBOARD_SESSION_TTL_SECONDS=3600
DASHBOARD_FRONTEND_URL=https://<dashboard-host>
```

The OAuth flow requests only `identify guilds`. APXOR grants dashboard access for guilds where the authenticated Discord user is the guild owner or has `ADMINISTRATOR` / `MANAGE_GUILD`.

## Security properties

- OAuth state is bound to a short-lived, HttpOnly cookie.
- The browser session is an HMAC-signed, HttpOnly cookie.
- Discord access tokens are never stored in the browser session.
- Dashboard API requests are authorized against the guild ID in the session.
- The existing service API key remains available for trusted server-to-server clients.
- Dashboard sessions expire automatically; use HTTPS in production so cookies are marked `Secure`.

## Endpoints

```text
GET  /api/dashboard/auth/login
GET  /api/dashboard/auth/callback
GET  /api/dashboard/auth/me
POST /api/dashboard/auth/logout
```

Guild-scoped dashboard endpoints now accept either the legacy service key or a valid Discord OAuth session that includes the requested guild.
