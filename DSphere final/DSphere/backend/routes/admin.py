"""
DSphere — routes/admin.py
Admin-only endpoints for system monitoring and management.

  GET    /admin/users                  – list all users
  PATCH  /admin/users/{uid}/suspend    – suspend a user account
  PATCH  /admin/users/{uid}/restore    – restore a suspended account
  DELETE /admin/users/{uid}            – permanently delete user
  GET    /admin/threats                – live threat feed (flagged IPs)
  GET    /admin/threats/history        – Firestore threat event log
  POST   /admin/threats/block-ip       – manually block an IP
  DELETE /admin/threats/unblock-ip/{ip}– manually unblock an IP
  PATCH  /admin/threats/reset-risk/{ip}– reset risk level for an IP
  GET    /admin/blocked-ips            – list all currently blocked IPs
  GET    /admin/stats                  – dashboard summary stats
"""

import logging
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from firebase_admin_init import get_db
from utils.jwt_handler import get_current_admin
from middleware.rate_limiter import brute_force
from middleware.threat_detection import get_all_risk_levels, reset_risk

logger = logging.getLogger("dsphere.admin")
router = APIRouter()

USERS_COLLECTION  = "users"
THREAT_COLLECTION = "threat_events"
FILES_COLLECTION  = "file_metadata"


# ── Pydantic ──────────────────────────────────────────────────────────────────
class BlockIpRequest(BaseModel):
    ip: str
    minutes: int = 30
    reason: str = "Manually blocked by admin"


class RoleChangeRequest(BaseModel):
    role: str   # 'user' | 'admin'


# ── User Management ───────────────────────────────────────────────────────────
@router.get("/users")
async def list_users(admin: dict = Depends(get_current_admin)):
    db   = get_db()
    docs = db.collection(USERS_COLLECTION).order_by("created_at").get()
    users = []
    for doc in docs:
        d = doc.to_dict()
        d.pop("password_hash", None)   # never expose hashes
        users.append({"uid": doc.id, **d})
    return {"success": True, "users": users, "count": len(users)}


@router.patch("/users/{uid}/suspend")
async def suspend_user(uid: str, admin: dict = Depends(get_current_admin)):
    if uid == admin["uid"]:
        raise HTTPException(status_code=400, detail="You cannot suspend your own account.")
    db  = get_db()
    doc = db.collection(USERS_COLLECTION).document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found.")
    db.collection(USERS_COLLECTION).document(uid).update({"active": False})
    logger.info("Admin %s suspended user %s", admin["email"], uid)
    return {"success": True, "message": f"User {uid} suspended."}


@router.patch("/users/{uid}/restore")
async def restore_user(uid: str, admin: dict = Depends(get_current_admin)):
    db  = get_db()
    doc = db.collection(USERS_COLLECTION).document(uid).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="User not found.")
    db.collection(USERS_COLLECTION).document(uid).update({"active": True})
    logger.info("Admin %s restored user %s", admin["email"], uid)
    return {"success": True, "message": f"User {uid} restored."}


@router.delete("/users/{uid}")
async def delete_user(uid: str, admin: dict = Depends(get_current_admin)):
    if uid == admin["uid"]:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    db = get_db()
    db.collection(USERS_COLLECTION).document(uid).delete()
    logger.info("Admin %s permanently deleted user %s", admin["email"], uid)
    return {"success": True, "message": f"User {uid} deleted."}


@router.patch("/users/{uid}/role")
async def change_role(uid: str, body: RoleChangeRequest, admin: dict = Depends(get_current_admin)):
    if body.role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="Role must be 'user' or 'admin'.")
    db = get_db()
    db.collection(USERS_COLLECTION).document(uid).update({"role": body.role})
    logger.info("Admin %s changed role of %s to %s", admin["email"], uid, body.role)
    return {"success": True, "message": f"Role updated to {body.role}."}


# ── Threat Feed ───────────────────────────────────────────────────────────────
@router.get("/threats")
async def live_threat_feed(admin: dict = Depends(get_current_admin)):
    """In-memory risk levels (real-time, current session)."""
    threats = get_all_risk_levels()
    blocked = brute_force.get_all_blocked()

    return {
        "success":       True,
        "threat_count":  len(threats),
        "blocked_count": len(blocked),
        "threats":       threats,
        "blocked_ips":   blocked,
    }


@router.get("/threats/history")
async def threat_history(
    limit: int = 50,
    admin: dict = Depends(get_current_admin),
):
    """Persistent threat events from Firestore."""
    db   = get_db()
    docs = (
        db.collection(THREAT_COLLECTION)
        .order_by("timestamp")
        .limit_to_last(limit)
        .get()
    )
    events = []
    for doc in docs:
        d = doc.to_dict()
        d["id"] = doc.id
        d["timestamp_iso"] = datetime.fromtimestamp(
            d.get("timestamp", 0), tz=timezone.utc
        ).isoformat()
        events.append(d)

    events.reverse()   # newest first
    return {"success": True, "events": events, "count": len(events)}


# ── IP Management ─────────────────────────────────────────────────────────────
@router.post("/threats/block-ip", status_code=201)
async def block_ip(body: BlockIpRequest, admin: dict = Depends(get_current_admin)):
    brute_force.manual_block(body.ip, body.minutes)

    # Log to Firestore
    db = get_db()
    db.collection(THREAT_COLLECTION).add({
        "ip":         body.ip,
        "uid":        None,
        "risk_level": "HIGH",
        "reasons":    [f"Manual admin block: {body.reason}"],
        "path":       "/admin/threats/block-ip",
        "timestamp":  time.time(),
    })

    logger.info("Admin %s manually blocked IP %s for %d min", admin["email"], body.ip, body.minutes)
    return {"success": True, "message": f"IP {body.ip} blocked for {body.minutes} minutes."}


@router.delete("/threats/unblock-ip/{ip}")
async def unblock_ip(ip: str, admin: dict = Depends(get_current_admin)):
    unblocked = brute_force.manual_unblock(ip)
    if not unblocked:
        return {"success": False, "message": f"IP {ip} was not in the block list."}
    logger.info("Admin %s unblocked IP %s", admin["email"], ip)
    return {"success": True, "message": f"IP {ip} unblocked."}


@router.patch("/threats/reset-risk/{ip}")
async def reset_ip_risk(ip: str, admin: dict = Depends(get_current_admin)):
    reset_risk(ip)
    logger.info("Admin %s reset risk level for IP %s", admin["email"], ip)
    return {"success": True, "message": f"Risk level reset for IP {ip}."}


@router.get("/blocked-ips")
async def list_blocked_ips(admin: dict = Depends(get_current_admin)):
    return {"success": True, "blocked_ips": brute_force.get_all_blocked()}


# ── Dashboard Stats ───────────────────────────────────────────────────────────
@router.get("/stats")
async def dashboard_stats(admin: dict = Depends(get_current_admin)):
    db = get_db()

    # User counts
    all_users  = db.collection(USERS_COLLECTION).get()
    total_u    = len(all_users)
    active_u   = sum(1 for d in all_users if d.to_dict().get("active", True))
    verified_u = sum(1 for d in all_users if d.to_dict().get("verified", False))

    # File counts
    all_files = db.collection(FILES_COLLECTION).get()
    total_f   = len(all_files)
    total_bytes = sum(d.to_dict().get("size_bytes", 0) for d in all_files)

    # Threat counts
    threats = get_all_risk_levels()
    high    = sum(1 for t in threats if t["risk_level"] == "HIGH")
    medium  = sum(1 for t in threats if t["risk_level"] == "MEDIUM")

    return {
        "success": True,
        "stats": {
            "users": {
                "total":    total_u,
                "active":   active_u,
                "verified": verified_u,
                "suspended": total_u - active_u,
            },
            "storage": {
                "total_files":      total_f,
                "total_bytes":      total_bytes,
                "total_mb":         round(total_bytes / (1024 * 1024), 2),
            },
            "security": {
                "blocked_ips":     len(brute_force.get_all_blocked()),
                "high_risk_ips":   high,
                "medium_risk_ips": medium,
                "total_flagged":   len(threats),
            },
        },
    }