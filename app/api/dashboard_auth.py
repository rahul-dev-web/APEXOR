from __future__ import annotations

import secrets
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from app.core.config import settings
from app.security.dashboard_auth import DashboardPrincipal, DashboardSessionSigner

router = APIRouter(prefix="/api/dashboard/auth", tags=["dashboard-auth"])

SESSION_COOKIE = "apxor_dashboard_session"
STATE_COOKIE = "apxor_dashboard_oauth_state"


def _signer() -> DashboardSessionSigner:
    try:
        return DashboardSessionSigner(settings.dashboard_session_secret, settings.dashboard_session_ttl_seconds)
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _oauth_configured() -> None:
    if not all((settings.discord_client_id, settings.discord_client_secret, settings.discord_redirect_uri)):
        raise HTTPException(status_code=503, detail="Discord dashboard OAuth is not configured.")


def _cookie_secure() -> bool:
    return settings.app_env.lower() not in {"development", "dev", "test"}


def _allowed_guild_ids(guilds: list[dict]) -> set[int]:
    allowed: set[int] = set()
    for guild in guilds:
        try:
            guild_id = int(guild["id"])
            is_owner = bool(guild.get("owner", False))
            permissions = int(guild.get("permissions", "0"))
        except (KeyError, TypeError, ValueError):
            continue
        # Discord ADMINISTRATOR = 0x8, MANAGE_GUILD = 0x20.
        if is_owner or (permissions & 0x8) or (permissions & 0x20):
            allowed.add(guild_id)
    return allowed


async def require_dashboard_guild_access(
    request: Request,
    guild_id: int,
    x_apxor_dashboard_key: str | None = Header(default=None),
    apxor_dashboard_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> DashboardPrincipal | None:
    # Preserve the server-to-server API-key path for internal tooling and tests.
    if settings.dashboard_api_key and x_apxor_dashboard_key and secrets.compare_digest(x_apxor_dashboard_key, settings.dashboard_api_key):
        return None

    if not apxor_dashboard_session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Dashboard login required.")
    try:
        principal = _signer().verify(apxor_dashboard_session)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired dashboard session.") from exc
    if guild_id not in principal.guild_ids:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have dashboard access to this guild.")
    return principal


@router.get("/login")
async def login() -> RedirectResponse:
    _oauth_configured()
    state = secrets.token_urlsafe(32)
    params = {
        "client_id": settings.discord_client_id,
        "redirect_uri": settings.discord_redirect_uri,
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
    }
    response = RedirectResponse("https://discord.com/oauth2/authorize?" + urlencode(params), status_code=302)
    response.set_cookie(STATE_COOKIE, state, max_age=600, httponly=True, secure=_cookie_secure(), samesite="lax", path="/")
    return response


@router.get("/callback")
async def callback(code: str, state: str, response: Response, oauth_state: str | None = Cookie(default=None, alias=STATE_COOKIE)) -> dict:
    _oauth_configured()
    if not oauth_state or not secrets.compare_digest(oauth_state, state):
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_response = await client.post(
            "https://discord.com/api/v10/oauth2/token",
            data={
                "client_id": settings.discord_client_id,
                "client_secret": settings.discord_client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.discord_redirect_uri,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_response.status_code >= 400:
            raise HTTPException(status_code=502, detail="Discord OAuth token exchange failed.")
        token = token_response.json().get("access_token")
        if not token:
            raise HTTPException(status_code=502, detail="Discord OAuth response did not contain an access token.")

        headers = {"Authorization": f"Bearer {token}"}
        user_response = await client.get("https://discord.com/api/v10/users/@me", headers=headers)
        guild_response = await client.get("https://discord.com/api/v10/users/@me/guilds", headers=headers)
        if user_response.status_code >= 400 or guild_response.status_code >= 400:
            raise HTTPException(status_code=502, detail="Discord identity lookup failed.")
        user = user_response.json()
        guilds = guild_response.json()

    try:
        user_id = int(user["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail="Discord returned an invalid user identity.") from exc

    allowed_guilds = _allowed_guild_ids(guilds)
    session_token = _signer().issue(user_id=user_id, guild_ids=allowed_guilds)
    redirect = RedirectResponse(settings.dashboard_frontend_url, status_code=302)
    redirect.set_cookie(SESSION_COOKIE, session_token, max_age=settings.dashboard_session_ttl_seconds, httponly=True, secure=_cookie_secure(), samesite="lax", path="/")
    redirect.delete_cookie(STATE_COOKIE, path="/")
    return redirect


@router.get("/me")
async def me(
    x_apxor_dashboard_key: str | None = Header(default=None),
    apxor_dashboard_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
) -> dict:
    if settings.dashboard_api_key and x_apxor_dashboard_key and secrets.compare_digest(x_apxor_dashboard_key, settings.dashboard_api_key):
        return {"authenticated": True, "mode": "service"}
    if not apxor_dashboard_session:
        raise HTTPException(status_code=401, detail="Dashboard login required.")
    try:
        principal = _signer().verify(apxor_dashboard_session)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired dashboard session.") from exc
    return {"authenticated": True, "mode": "discord_oauth", "user_id": principal.user_id, "guild_ids": sorted(principal.guild_ids), "expires_at": principal.expires_at}


@router.post("/logout")
async def logout(response: Response) -> dict[str, str]:
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "logged_out"}
