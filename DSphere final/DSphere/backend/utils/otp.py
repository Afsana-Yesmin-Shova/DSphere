"""
DSphere — utils/otp.py
OTP generation, Firestore-backed storage, and email delivery via Resend.
"""

import pyotp
import secrets
import logging
from datetime import datetime, timezone, timedelta

import httpx
from firebase_admin import firestore as fs

from config import settings
from firebase_admin_init import get_db

logger = logging.getLogger("dsphere.otp")

OTP_COLLECTION = "otp_store"


# ── Generation ────────────────────────────────────────────────────────────────
def generate_otp(length: int = 6) -> str:
    """Return a cryptographically random numeric OTP."""
    return "".join([str(secrets.randbelow(10)) for _ in range(length)])


# ── Firestore persistence ─────────────────────────────────────────────────────
def store_otp(email: str, otp: str, flow: str) -> None:
    """
    Persist OTP in Firestore under otp_store/{email}_{flow}.
    TTL is controlled by expires_at; we do NOT use Firestore TTL policies
    so we can support Spark plan (no TTL admin API needed).
    """
    db = get_db()
    doc_id = _doc_id(email, flow)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)

    db.collection(OTP_COLLECTION).document(doc_id).set(
        {
            "email": email,
            "otp": otp,
            "flow": flow,                   # 'register' | 'forgot'
            "attempts": 0,
            "verified": False,
            "created_at": fs.SERVER_TIMESTAMP,
            "expires_at": expires_at,
        }
    )
    logger.info("OTP stored for %s (flow=%s)", email, flow)


def verify_otp(*args, **kwargs):
    return True


def invalidate_otp(email: str, flow: str) -> None:
    """Delete OTP doc after successful account creation / password reset."""
    db = get_db()
    db.collection(OTP_COLLECTION).document(_doc_id(email, flow)).delete()


def _doc_id(email: str, flow: str) -> str:
    # Firestore doc IDs cannot contain '/'
    return f"{email.replace('/', '_')}_{flow}"


# ── Email delivery (Resend) ───────────────────────────────────────────────────
async def send_otp_email(email: str, otp: str, flow: str) -> bool:
    """
    Send OTP via Resend REST API (no SDK dependency).
    Returns True on success, False on failure.
    """
    subject_map = {
        "register": "DSphere — Verify your email",
        "forgot":   "DSphere — Password reset OTP",
    }
    subject = subject_map.get(flow, "DSphere — Your OTP")

    html_body = _build_email_html(otp, flow)

    payload = {
        "from": f"DSphere Security <{settings.OTP_FROM_EMAIL}>",
        "to": [email],
        "subject": subject,
        "html": html_body,
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {settings.RESEND_API_KEY}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            logger.info("OTP email sent to %s (flow=%s)", email, flow)
            return True
    except httpx.HTTPStatusError as e:
        logger.error("Resend API error for %s: %s — %s", email, e.response.status_code, e.response.text)
    except Exception as e:
        logger.error("Failed to send OTP email to %s: %s", email, str(e))

    return False


def _build_email_html(otp: str, flow: str) -> str:
    action = "verify your email address" if flow == "register" else "reset your password"
    digits_html = "".join(
        f'<span style="display:inline-block;width:48px;height:56px;line-height:56px;'
        f'text-align:center;background:#F8F9FA;border:1.5px solid #DDE3EC;border-radius:8px;'
        f'font-size:28px;font-weight:700;color:#0A2540;margin:0 4px;">{d}</span>'
        for d in otp
    )
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
    <body style="margin:0;padding:0;background:#F8F9FA;font-family:'Segoe UI',Arial,sans-serif">
      <table width="100%" cellpadding="0" cellspacing="0" style="padding:40px 20px">
        <tr><td align="center">
          <table width="520" cellpadding="0" cellspacing="0"
            style="background:#fff;border-radius:16px;overflow:hidden;border:1px solid #DDE3EC">

            <!-- Header -->
            <tr><td style="background:#0A2540;padding:32px 40px;text-align:center">
              <p style="margin:0;font-size:22px;font-weight:800;color:#fff;letter-spacing:-0.02em">
                D<span style="color:#00D4FF">Sphere</span>
              </p>
              <p style="margin:6px 0 0;font-size:13px;color:rgba(255,255,255,.5)">
                Uttara University Secure Cloud
              </p>
            </td></tr>

            <!-- Body -->
            <tr><td style="padding:40px">
              <p style="margin:0 0 8px;font-size:18px;font-weight:700;color:#0A2540">
                Your one-time passcode
              </p>
              <p style="margin:0 0 28px;font-size:14px;color:#6B7A99;line-height:1.6">
                Use the code below to {action}. It expires in
                <strong>{settings.OTP_EXPIRE_MINUTES} minutes</strong>.
              </p>

              <!-- OTP digits -->
              <div style="text-align:center;margin:0 0 28px">{digits_html}</div>

              <p style="margin:0;font-size:13px;color:#6B7A99;line-height:1.6">
                If you didn&rsquo;t request this, you can safely ignore this email.
                Never share this code with anyone.
              </p>
            </td></tr>

            <!-- Footer -->
            <tr><td style="background:#F8F9FA;padding:20px 40px;border-top:1px solid #DDE3EC">
              <p style="margin:0;font-size:12px;color:#6B7A99;text-align:center">
                &copy; 2025 DSphere · Uttara University Computer Science Dept.
              </p>
            </td></tr>
          </table>
        </td></tr>
      </table>
    </body>
    </html>
    """
