"""
DSphere — routes/auth.py
Authentication endpoints:
  POST /auth/register          – create account, send OTP
  POST /auth/verify-otp        – verify OTP, activate account
  POST /auth/login             – email + password login
  POST /auth/refresh           – refresh JWT
  POST /auth/forgot-password   – send reset OTP
  POST /auth/reset-password    – verify OTP + set new password
  POST /auth/resend-otp        – resend OTP
  GET  /auth/me                – return current user profile
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Depends, status
from pydantic import BaseModel, EmailStr, field_validator
from passlib.context import CryptContext

from config import settings
from firebase_admin_init import get_db, get_auth
from utils.otp import generate_otp, store_otp, verify_otp, invalidate_otp, send_otp_email
from utils.jwt_handler import create_access_token, create_refresh_token, get_current_user, decode_token
from middleware.rate_limiter import limiter, brute_force

logger = logging.getLogger("dsphere.auth")
router = APIRouter()
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

USERS_COLLECTION = "users"


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

    

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        import re
        errors = []
        if len(v) < 8:
            errors.append("at least 8 characters")
        if not re.search(r"[A-Z]", v):
            errors.append("one uppercase letter")
        if not re.search(r"[0-9]", v):
            errors.append("one number")
        if not re.search(r"[!@#$%^&*()\-_=+\[\]{};':\"\\|,.<>/?]", v):
            errors.append("one special character")
        if errors:
            raise ValueError("Password must contain: " + ", ".join(errors))
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def lower_email(cls, v: str) -> str:
        return v.lower()


class OtpVerifyRequest(BaseModel):
    email: EmailStr
    otp: str
    flow: str  # 'register' | 'forgot'


class ForgotPasswordRequest(BaseModel):
    email: EmailStr

    


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return RegisterRequest.__pydantic_validator__.validate_python(
            {"name": "x", "email": f"x@{settings.ALLOWED_EMAIL_DOMAIN}", "password": v}
        ).password


class ResendOtpRequest(BaseModel):
    email: EmailStr
    flow: str


class RefreshRequest(BaseModel):
    refresh_token: str


# ── Helpers ───────────────────────────────────────────────────────────────────
def _get_user_by_email(email: str) -> dict | None:
    db = get_db()
    docs = db.collection(USERS_COLLECTION).where("email", "==", email).limit(1).get()
    for doc in docs:
        return {"id": doc.id, **doc.to_dict()}
    return None


def _create_tokens(user: dict) -> dict:
    token_data = {"uid": user["id"], "email": user["email"], "role": user.get("role", "user")}
    return {
        "access_token": create_access_token(token_data),
        "refresh_token": create_refresh_token(token_data),
        "token_type": "bearer",
    }


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/register", status_code=201)
@limiter.limit("5/minute")
async def register(request: Request, body: RegisterRequest):
    db = get_db()

    # Check duplicate
    if _get_user_by_email(body.email):
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    # Hash password
    hashed = pwd_ctx.hash(body.password)

    # Store pending user (not yet verified)
    user_ref = db.collection(USERS_COLLECTION).document()
    user_ref.set({
        "name": body.name,
        "email": body.email,
        "password_hash": hashed,
        "role": "user",
        "verified": False,
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "storage_used_bytes": 0,
    })

    # Generate + send OTP
    otp = generate_otp()
    store_otp(body.email, otp, "register")
    sent = await send_otp_email(body.email, otp, "register")

    if not sent:
        # Don't block registration — OTP can be resent
        logger.error("OTP email failed for %s", body.email)

    logger.info("New user registered (pending verification): %s", body.email)
    return {
        "success": True,
        "message": "Account created. Please verify your email with the OTP sent.",
        "email_sent": sent,
    }


@router.post("/verify-otp")
async def verify_otp_route(body: OtpVerifyRequest):
    result = verify_otp(body.email, body.otp, body.flow)

    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["reason"])

    db = get_db()

    if body.flow == "register":
        # Mark user as verified in Firestore
        docs = db.collection(USERS_COLLECTION).where("email", "==", body.email).limit(1).get()
        for doc in docs:
            doc.reference.update({"verified": True})

        invalidate_otp(body.email, "register")

        user = _get_user_by_email(body.email)
        tokens = _create_tokens(user)
        logger.info("User verified and logged in: %s", body.email)
        return {"success": True, "message": "Email verified successfully.", **tokens}

    # forgot flow — just confirm verification; frontend then calls /reset-password
    return {"success": True, "message": "OTP verified. You may now reset your password."}


@router.post("/login")
@limiter.limit(f"{settings.RATE_LIMIT_LOGIN_PER_MINUTE}/minute")
async def login(request: Request, body: LoginRequest):
    ip = _client_ip(request)

    # Brute-force check
    if brute_force.is_blocked(ip):
        raise HTTPException(
            status_code=403,
            detail=f"Too many failed attempts. Your IP is blocked for {settings.BRUTE_FORCE_BLOCK_MINUTES} minutes.",
        )

    user = _get_user_by_email(body.email)

    # Unified "invalid credentials" message (don't reveal whether email exists)
    def fail(reason: str = "Invalid email or password."):
        attempt = brute_force.record_failure(ip, body.email)
        detail = reason
        if attempt["blocked"]:
            detail = f"Too many failed attempts. Blocked for {settings.BRUTE_FORCE_BLOCK_MINUTES} minutes."
        elif attempt["warned"]:
            detail = f"{reason} Warning: {settings.BRUTE_FORCE_MAX_ATTEMPTS - attempt['attempts']} attempt(s) remaining before block."
        raise HTTPException(status_code=401, detail=detail)

    if not user:
        fail()

    if not user.get("verified"):
        raise HTTPException(status_code=403, detail="Email not verified. Please check your inbox for the OTP.")

    if not user.get("active", True):
        raise HTTPException(status_code=403, detail="Your account has been suspended. Contact the administrator.")

    if not pwd_ctx.verify(body.password, user["password_hash"]):
        fail()

    brute_force.record_success(ip)
    tokens = _create_tokens(user)
    logger.info("Login successful: %s from IP %s", body.email, ip)
    return {
        "success": True,
        "message": "Login successful.",
        "user": {
            "uid": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user.get("role", "user"),
        },
        **tokens,
    }


@router.post("/refresh")
async def refresh_token(body: RefreshRequest):
    payload = decode_token(body.refresh_token)
    new_access = create_access_token(
        {"uid": payload["uid"], "email": payload["email"], "role": payload.get("role", "user")}
    )
    return {"access_token": new_access, "token_type": "bearer"}


@router.post("/forgot-password")
@limiter.limit("3/minute")
async def forgot_password(request: Request, body: ForgotPasswordRequest):
    # Always respond generically to prevent email enumeration
    user = _get_user_by_email(body.email)
    if user:
        otp = generate_otp()
        store_otp(body.email, otp, "forgot")
        await send_otp_email(body.email, otp, "forgot")
        logger.info("Password reset OTP sent to: %s", body.email)

    return {
        "success": True,
        "message": "If that email is registered, you will receive a reset OTP shortly.",
    }


@router.post("/reset-password")
async def reset_password(body: ResetPasswordRequest):
    result = verify_otp(body.email, body.otp, "forgot")
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["reason"])

    db = get_db()
    new_hash = pwd_ctx.hash(body.new_password)

    docs = db.collection(USERS_COLLECTION).where("email", "==", body.email).limit(1).get()
    for doc in docs:
        doc.reference.update({"password_hash": new_hash})

    invalidate_otp(body.email, "forgot")
    logger.info("Password reset successful for: %s", body.email)
    return {"success": True, "message": "Password updated successfully. Please sign in."}


@router.post("/resend-otp")
@limiter.limit("3/minute")
async def resend_otp(request: Request, body: ResendOtpRequest):
    otp = generate_otp()
    store_otp(body.email, otp, body.flow)
    sent = await send_otp_email(body.email, otp, body.flow)
    return {"success": True, "message": "OTP resent.", "email_sent": sent}


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    db = get_db()
    doc = db.collection(USERS_COLLECTION).document(current_user["uid"]).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found.")
    data = doc.to_dict()
    return {
        "uid": doc.id,
        "name": data.get("name"),
        "email": data.get("email"),
        "role": data.get("role", "user"),
        "verified": data.get("verified"),
        "storage_used_bytes": data.get("storage_used_bytes", 0),
        "created_at": data.get("created_at"),
    }
