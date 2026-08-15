from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    log_level: str = "INFO"

    discord_token: str = ""
    discord_client_id: str = ""
    discord_client_secret: str = ""
    discord_redirect_uri: str = "http://localhost:8000/api/dashboard/auth/callback"
    database_url: str = ""

    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-20b"

    # Legacy service-to-service authentication for internal tooling.
    dashboard_api_key: str = ""

    # Browser-facing dashboard session configuration. The secret must never be
    # exposed to the frontend or sent to Discord.
    dashboard_session_secret: str = ""
    dashboard_session_ttl_seconds: int = 3600
    dashboard_frontend_url: str = "http://localhost:3000"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
