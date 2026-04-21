"""
DSphere — firebase_admin_init.py
Initialises the Firebase Admin SDK once using a service-account dict
built from individual environment variables (no JSON file needed on Render).
"""

import firebase_admin
from firebase_admin import credentials, firestore, auth as fb_auth, storage as fb_storage
from config import settings
import logging

logger = logging.getLogger("dsphere.firebase")

_app: firebase_admin.App | None = None


def get_firebase_app() -> firebase_admin.App:
    """Return the singleton Firebase Admin app, initialising it if needed."""
    global _app
    if _app is not None:
        return _app

    service_account = {
        "type": "service_account",
        "project_id": settings.FIREBASE_PROJECT_ID,
        "private_key_id": settings.FIREBASE_PRIVATE_KEY_ID,
        # .env stores \n literally; replace to get real newlines
        "private_key": settings.FIREBASE_PRIVATE_KEY.replace("\\n", "\n"),
        "client_email": settings.FIREBASE_CLIENT_EMAIL,
        "client_id": settings.FIREBASE_CLIENT_ID,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }

    cred = credentials.Certificate(service_account)
    _app = firebase_admin.initialize_app(
        cred,
        {"storageBucket": settings.FIREBASE_STORAGE_BUCKET},
    )
    logger.info("Firebase Admin SDK initialised for project: %s", settings.FIREBASE_PROJECT_ID)
    return _app


# ── Convenience accessors ─────────────────────────────────────────────────────
def get_db():
    """Return Firestore client."""
    get_firebase_app()
    return firestore.client()


def get_auth():
    """Return Firebase Auth client."""
    get_firebase_app()
    return fb_auth


def get_bucket():
    """Return Firebase Storage bucket."""
    get_firebase_app()
    return fb_storage.bucket()