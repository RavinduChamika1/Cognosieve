import os
from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional

# Resolve .env paths relative to this file (backend/) so they work
# regardless of CWD when uvicorn runs from project root or backend/
_HERE = Path(__file__).parent
_ROOT = _HERE.parent


class Settings(BaseSettings):
    APP_NAME: str = "CognoSieve"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Security & API Keys
    GEMINI_API_KEY: Optional[str] = None
    ZAP_API_KEY: str = "cognosieve_secret_key"
    ZAP_BASE_URL: str = "http://localhost:8080"
    GEMINI_MODEL: str = "gemini-3.8-flash"

    # Server configuration
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    CORS_ORIGINS: list[str] = ["*"]

    # Storage paths
    DATABASE_PATH: str = "cognosieve.db"
    REPORTS_DIR: str = "reports"

    class Config:
        env_file = (
            str(_HERE / ".env"),
            str(_ROOT / ".env"),
            str(_HERE / ".env.example"),
            str(_ROOT / ".env.example"),
        )
        extra = "ignore"


settings = Settings()

# Ensure reports directory exists
Path(settings.REPORTS_DIR).mkdir(parents=True, exist_ok=True)
