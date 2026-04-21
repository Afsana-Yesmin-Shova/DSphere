"""
DSphere — middleware/threat_detection.py
Starlette middleware that intercepts every request and monitors for:
  • Excessive file downloads (>20 in a rolling 5-minute window)
  • Access to restricted paths (admin routes by non-admins)
  • Unusual upload patterns (many uploads in short time)
  • Blocked IP attempting to connect

Risk levels: LOW | MEDIUM | HIGH
All events are persisted to Firestore collection: threat_events
"""

import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from firebase_admin_init import get_db
from config import settings

logger = logging.getLogger("dsphere.threat")

# ── Constants ─────────────────────────────────────────────────────────────────
WINDOW_SECONDS       = 300          # 5-minute rolling window
DOWNLOAD_THRESHOLD   = 20           # downloads per window → HIGH risk
UPLOAD_THRESHOLD     = 30           # uploads per window → MEDIUM risk
RESTRICTED_PREFIXES  = ["/admin"]   # paths requiring admin role

RISK_LOW    = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH   = "HIGH"


# ── Per-IP behaviour record ───────────────────────────────────────────────────
@dataclass
class BehaviourRecord:
    download_times: List[float] = field(default_factory=list)
    upload_times:   List[float] = field(default_factory=list)
    risk_level:     str = RISK_LOW
    flagged_reasons: List[str] = field(default_factory=list)


_behaviour: Dict[str, BehaviourRecord] = defaultdict(BehaviourRecord)


def _prune_window(times: List[float]) -> List[float]:
    cutoff = time.time() - WINDOW_SECONDS
    return [t for t in times if t > cutoff]


# ── Firestore event logger ────────────────────────────────────────────────────
def _log_threat_event(ip: str, uid: str | None, risk: str, reasons: list[str], path: str):
    try:
        db = get_db()
        db.collection("threat_events").add({
            "ip": ip,
            "uid": uid,
            "risk_level": risk,
            "reasons": reasons,
            "path": path,
            "timestamp": time.time(),
        })
    except Exception as e:
        logger.error("Failed to log threat event: %s", e)


# ── Public API for admin panel ────────────────────────────────────────────────
def get_all_risk_levels() -> list[dict]:
    return [
        {
            "ip": ip,
            "risk_level": rec.risk_level,
            "reasons": rec.flagged_reasons,
            "downloads_in_window": len(_prune_window(rec.download_times)),
            "uploads_in_window":   len(_prune_window(rec.upload_times)),
        }
        for ip, rec in _behaviour.items()
        if rec.risk_level != RISK_LOW
    ]


def reset_risk(ip: str) -> bool:
    if ip in _behaviour:
        del _behaviour[ip]
        return True
    return False


# ── Middleware ─────────────────────────────────────────────────────────────────
class ThreatDetectionMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next) -> Response:
        ip  = request.client.host if request.client else "unknown"
        path = request.url.path

        # ── Check if IP is manually blocked ───────────────────────────────────
        # (Import here to avoid circular; brute_force store is the source of truth)
        from middleware.rate_limiter import brute_force
        if brute_force.is_blocked(ip):
            return JSONResponse(
                status_code=403,
                content={
                    "success": False,
                    "message": "Your IP has been temporarily blocked due to suspicious activity.",
                },
            )

        # ── Process request ───────────────────────────────────────────────────
        response: Response = await call_next(request)

        # ── Post-response analysis ────────────────────────────────────────────
        rec = _behaviour[ip]
        now = time.time()
        reasons: list[str] = []
        uid: str | None = None

        # Attempt to get UID from token (non-blocking)
        try:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                from utils.jwt_handler import decode_token
                payload = decode_token(auth_header.split(" ", 1)[1])
                uid = payload.get("uid")
        except Exception:
            pass

        # Track downloads
        if path.startswith("/storage/download") and response.status_code == 200:
            rec.download_times.append(now)
            rec.download_times = _prune_window(rec.download_times)
            if len(rec.download_times) >= DOWNLOAD_THRESHOLD:
                reasons.append(f"Excessive downloads: {len(rec.download_times)} in 5 min")

        # Track uploads
        if path.startswith("/storage/upload") and request.method == "POST" and response.status_code == 200:
            rec.upload_times.append(now)
            rec.upload_times = _prune_window(rec.upload_times)
            if len(rec.upload_times) >= UPLOAD_THRESHOLD:
                reasons.append(f"Excessive uploads: {len(rec.upload_times)} in 5 min")

        # Restricted path access by non-admin (403 response)
        if any(path.startswith(p) for p in RESTRICTED_PREFIXES) and response.status_code == 403:
            reasons.append(f"Unauthorised admin path access: {path}")

        # Assign risk level
        if reasons:
            # Escalate — never downgrade
            if len(reasons) >= 2 or any("Excessive downloads" in r for r in reasons):
                new_risk = RISK_HIGH
            else:
                new_risk = RISK_MEDIUM

            if _risk_rank(new_risk) > _risk_rank(rec.risk_level):
                rec.risk_level = new_risk

            rec.flagged_reasons = list(set(rec.flagged_reasons + reasons))

            logger.warning(
                "THREAT | IP=%s UID=%s risk=%s reasons=%s",
                ip, uid, rec.risk_level, reasons,
            )
            _log_threat_event(ip, uid, rec.risk_level, reasons, path)

        return response


def _risk_rank(level: str) -> int:
    return {RISK_LOW: 0, RISK_MEDIUM: 1, RISK_HIGH: 2}.get(level, 0)
