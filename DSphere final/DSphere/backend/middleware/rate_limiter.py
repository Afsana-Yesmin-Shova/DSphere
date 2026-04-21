"""
DSphere — middleware/rate_limiter.py
SlowAPI-based rate limiting + in-memory brute-force tracker.

Brute-force rules:
  - 3 failed login attempts  → warning logged, risk level elevated to MEDIUM
  - 5 failed login attempts  → IP blocked for BRUTE_FORCE_BLOCK_MINUTES
"""

import time
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from config import settings

logger = logging.getLogger("dsphere.rate_limiter")

# ── SlowAPI limiter (uses client IP as key) ───────────────────────────────────
limiter = Limiter(key_func=get_remote_address)


def setup_rate_limiter(app: FastAPI) -> Limiter:
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
    return limiter


async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "success": False,
            "message": "Too many requests. Please slow down and try again.",
        },
    )


# ── In-memory brute-force store ───────────────────────────────────────────────
@dataclass
class LoginAttemptRecord:
    count: int = 0
    blocked_until: float = 0.0          # epoch seconds; 0 = not blocked
    warned: bool = False
    email_attempts: Dict[str, int] = field(default_factory=dict)


_attempts: Dict[str, LoginAttemptRecord] = defaultdict(LoginAttemptRecord)


class BruteForceProtector:
    """
    Tracks failed login attempts per IP address.
    Thread-safe enough for single-worker deployments.
    For multi-worker, replace with Redis.
    """

    @staticmethod
    def is_blocked(ip: str) -> bool:
        rec = _attempts[ip]
        if rec.blocked_until and time.time() < rec.blocked_until:
            return True
        if rec.blocked_until and time.time() >= rec.blocked_until:
            # Block expired — reset
            _attempts[ip] = LoginAttemptRecord()
        return False

    @staticmethod
    def record_failure(ip: str, email: str) -> dict:
        """
        Record a failed login attempt.
        Returns a dict describing current state:
          { "blocked": bool, "warned": bool, "attempts": int }
        """
        rec = _attempts[ip]
        rec.count += 1
        rec.email_attempts[email] = rec.email_attempts.get(email, 0) + 1

        result = {"blocked": False, "warned": False, "attempts": rec.count}

        if rec.count >= settings.BRUTE_FORCE_MAX_ATTEMPTS:
            block_until = time.time() + settings.BRUTE_FORCE_BLOCK_MINUTES * 60
            rec.blocked_until = block_until
            result["blocked"] = True
            logger.warning(
                "BRUTE-FORCE BLOCK | IP=%s email=%s attempts=%d blocked_for=%dmin",
                ip, email, rec.count, settings.BRUTE_FORCE_BLOCK_MINUTES,
            )
        elif rec.count >= settings.BRUTE_FORCE_WARN_ATTEMPTS and not rec.warned:
            rec.warned = True
            result["warned"] = True
            logger.warning(
                "BRUTE-FORCE WARNING | IP=%s email=%s attempts=%d",
                ip, email, rec.count,
            )

        return result

    @staticmethod
    def record_success(ip: str) -> None:
        """Clear attempt counter after a successful login."""
        if ip in _attempts:
            del _attempts[ip]

    @staticmethod
    def get_all_blocked() -> list[dict]:
        """Return all currently blocked IPs (used by admin panel)."""
        now = time.time()
        return [
            {
                "ip": ip,
                "attempts": rec.count,
                "blocked_until": rec.blocked_until,
                "seconds_remaining": max(0, int(rec.blocked_until - now)),
            }
            for ip, rec in _attempts.items()
            if rec.blocked_until and now < rec.blocked_until
        ]

    @staticmethod
    def manual_unblock(ip: str) -> bool:
        """Admin: manually unblock an IP."""
        if ip in _attempts:
            del _attempts[ip]
            logger.info("Admin manually unblocked IP: %s", ip)
            return True
        return False

    @staticmethod
    def manual_block(ip: str, minutes: int | None = None) -> None:
        """Admin: manually block an IP."""
        duration = (minutes or settings.BRUTE_FORCE_BLOCK_MINUTES) * 60
        rec = _attempts[ip]
        rec.blocked_until = time.time() + duration
        rec.count = settings.BRUTE_FORCE_MAX_ATTEMPTS
        logger.info("Admin manually blocked IP: %s for %d minutes", ip, minutes or settings.BRUTE_FORCE_BLOCK_MINUTES)


brute_force = BruteForceProtector()