"""
DSphere — config.py
Centralised settings loaded from environment / .env file.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # ── Firebase ──────────────────────────────────────────────────────────────
    FIREBASE_PROJECT_ID: str
    FIREBASE_PRIVATE_KEY_ID: str
    FIREBASE_PRIVATE_KEY: str          # newlines as \n in .env
    FIREBASE_CLIENT_EMAIL: str
    FIREBASE_CLIENT_ID: str
    FIREBASE_STORAGE_BUCKET: str

    # ── Cloudinary ──────────────────────────────────────────────────────────────
    CLOUDINARY_CLOUD_NAME: str
    CLOUDINARY_API_KEY: str
    CLOUDINARY_API_SECRET: str

    # ── JWT ───────────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    # ── Email / OTP ───────────────────────────────────────────────────────────
    RESEND_API_KEY: str
    OTP_FROM_EMAIL: str = "noreply@uttarauniversity.edu.bd"
    OTP_EXPIRE_MINUTES: int = 2

    # ── App ───────────────────────────────────────────────────────────────────
    ALLOWED_EMAIL_DOMAIN: str = "uttarauniversity.edu.bd"
    FRONTEND_URL: str = "https://your-site.netlify.app"
    ENVIRONMENT: str = "development"

    # ── Brute-force / Rate limits ─────────────────────────────────────────────
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 10
    BRUTE_FORCE_MAX_ATTEMPTS: int = 5
    BRUTE_FORCE_WARN_ATTEMPTS: int = 3
    BRUTE_FORCE_BLOCK_MINUTES: int = 30

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()