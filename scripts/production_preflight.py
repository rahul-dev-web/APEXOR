"""Validate production environment prerequisites without exposing secrets.

This check is intentionally non-destructive. It only reads environment variables
and validates security-sensitive deployment configuration before a Render release.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str


REQUIRED = (
    "DISCORD_TOKEN",
    "DATABASE_URL",
    "DISCORD_CLIENT_ID",
    "DISCORD_CLIENT_SECRET",
    "DISCORD_REDIRECT_URI",
    "DASHBOARD_FRONTEND_URL",
    "DASHBOARD_SESSION_SECRET",
)


def _has_value(name: str) -> bool:
    return bool(os.getenv(name, "").strip())


def _is_https_public_url(value: str) -> bool:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        return False
    host = (parsed.hostname or "").lower()
    return host not in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def validate_environment() -> list[CheckResult]:
    results: list[CheckResult] = []
    app_env = os.getenv("APP_ENV", "").strip().lower()

    results.append(
        CheckResult(
            "APP_ENV",
            app_env == "production",
            "must be exactly 'production' for this preflight",
        )
    )

    for name in REQUIRED:
        results.append(
            CheckResult(
                name,
                _has_value(name),
                "configured" if _has_value(name) else "missing",
            )
        )

    session_secret = os.getenv("DASHBOARD_SESSION_SECRET", "")
    results.append(
        CheckResult(
            "DASHBOARD_SESSION_SECRET length",
            len(session_secret) >= 32,
            "minimum 32 characters" if len(session_secret) < 32 else "strong enough for session signing",
        )
    )

    redirect_uri = os.getenv("DISCORD_REDIRECT_URI", "").strip()
    results.append(
        CheckResult(
            "DISCORD_REDIRECT_URI",
            _is_https_public_url(redirect_uri),
            "must be an HTTPS public callback URL in production",
        )
    )

    frontend_url = os.getenv("DASHBOARD_FRONTEND_URL", "").strip()
    results.append(
        CheckResult(
            "DASHBOARD_FRONTEND_URL",
            _is_https_public_url(frontend_url),
            "must be an HTTPS public dashboard URL in production",
        )
    )

    database_url = os.getenv("DATABASE_URL", "").strip().lower()
    results.append(
        CheckResult(
            "DATABASE_URL scheme",
            database_url.startswith(("postgresql://", "postgres://")),
            "must use PostgreSQL in production",
        )
    )

    # Groq is deliberately optional: deterministic security must remain
    # operational when the advisory AI service is unavailable.
    groq_configured = bool(os.getenv("GROQ_API_KEY", "").strip())
    results.append(
        CheckResult(
            "GROQ_API_KEY",
            True,
            "configured" if groq_configured else "not configured (AI advisory layer will be degraded)",
        )
    )

    return results


def main() -> int:
    results = validate_environment()
    failures = 0
    print("APEXOR production preflight")
    print("=" * 30)
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        print(f"[{status}] {result.name}: {result.detail}")
        if not result.ok:
            failures += 1

    print()
    if failures:
        print(f"Preflight failed: {failures} check(s) require attention.")
        return 1

    print("Preflight passed: production environment prerequisites are present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
