"""
DSphere — routes/storage.py
Cloud Storage endpoints backed by Cloudinary (free tier).

  POST   /storage/upload        – upload a file (authenticated)
  GET    /storage/files         – list user's files
  GET    /storage/download/{id} – get direct download URL
  DELETE /storage/delete/{id}   – delete file (owner or admin)
  GET    /storage/all           – list ALL files (admin only)
"""

import re
import logging
import mimetypes
import hashlib
from datetime import datetime, timezone
from pathlib import PurePosixPath

import cloudinary
import cloudinary.uploader
import cloudinary.api

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from firebase_admin_init import get_db
from utils.jwt_handler import get_current_user, get_current_admin
from utils.file_validator import validate_file
from config import settings
from middleware.rate_limiter import limiter

logger = logging.getLogger("dsphere.storage")
router = APIRouter()

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".pdf", ".docx", ".ppt", ".pptx", ".xml"}
MAX_FILE_SIZE_MB   = 50
FILES_COLLECTION   = "file_metadata"

# ── Cloudinary config ─────────────────────────────────────────────────────────
cloudinary.config(
    cloud_name = settings.CLOUDINARY_CLOUD_NAME,
    api_key    = settings.CLOUDINARY_API_KEY,
    api_secret = settings.CLOUDINARY_API_SECRET,
    secure     = True,
)


# ── Upload ────────────────────────────────────────────────────────────────────
@router.post("/upload", status_code=201)
@limiter.limit("30/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    uid   = current_user["uid"]
    email = current_user["email"]

    # Extension check
    suffix = PurePosixPath(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"File type '{suffix}' not allowed. Permitted: {', '.join(ALLOWED_EXTENSIONS)}",
        )

    # Read content
    content = await file.read()

    # Size check
    size_mb = len(content) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        raise HTTPException(status_code=413, detail=f"File exceeds {MAX_FILE_SIZE_MB} MB limit.")

    # Deep content validation
    validation = validate_file(content, suffix, file.filename or "")
    if not validation["safe"]:
        logger.warning("MALICIOUS FILE BLOCKED | user=%s file=%s reason=%s", email, file.filename, validation["reason"])
        raise HTTPException(status_code=422, detail=f"File rejected: {validation['reason']}")

    # Build Cloudinary public_id
    safe_name = _safe_filename(file.filename or "upload")
    public_id = f"dsphere/users/{uid}/{safe_name}"
    content_type = (
        file.content_type
        or mimetypes.guess_type(file.filename or "")[0]
        or "application/octet-stream"
    )

    # Upload to Cloudinary
    try:
        result = cloudinary.uploader.upload(
            content,
            public_id     = public_id,
            resource_type = "raw",
            use_filename  = False,
            overwrite     = False,
        )
        download_url  = result["secure_url"]
        cloudinary_id = result["public_id"]
    except Exception as e:
        logger.error("Cloudinary upload failed: %s", str(e))
        raise HTTPException(status_code=500, detail="File upload failed. Please try again.")

    # Save metadata to Firestore
    db      = get_db()
    sha256  = hashlib.sha256(content).hexdigest()
    doc_ref = db.collection(FILES_COLLECTION).document()
    doc_ref.set({
        "uid":           uid,
        "owner_email":   email,
        "filename":      safe_name,
        "original_name": file.filename,
        "cloudinary_id": cloudinary_id,
        "download_url":  download_url,
        "size_bytes":    len(content),
        "content_type":  content_type,
        "sha256":        sha256,
        "uploaded_at":   datetime.now(timezone.utc).isoformat(),
    })

    # Update user storage quota
    db.collection("users").document(uid).update(
        {"storage_used_bytes": _increment_storage(uid, len(content))}
    )

    logger.info("Uploaded to Cloudinary: %s by %s (%d bytes)", cloudinary_id, email, len(content))
    return {
        "success":    True,
        "message":    "File uploaded successfully.",
        "file_id":    doc_ref.id,
        "filename":   safe_name,
        "size_bytes": len(content),
    }


# ── List user files ───────────────────────────────────────────────────────────
@router.get("/files")
async def list_files(current_user: dict = Depends(get_current_user)):
    db  = get_db()
    uid = current_user["uid"]
    docs = (
        db.collection(FILES_COLLECTION)
        .where("uid", "==", uid)
        .order_by("uploaded_at")
        .get()
    )
    return {
        "success": True,
        "files":   [{"id": d.id, **d.to_dict()} for d in docs],
        "count":   len(docs),
    }


# ── Download ──────────────────────────────────────────────────────────────────
@router.get("/download/{file_id}")
async def download_file(file_id: str, current_user: dict = Depends(get_current_user)):
    db  = get_db()
    doc = db.collection(FILES_COLLECTION).document(file_id).get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="File not found.")

    data = doc.to_dict()
    uid  = current_user["uid"]
    role = current_user.get("role", "user")

    if data["uid"] != uid and role != "admin":
        raise HTTPException(status_code=403, detail="Access denied.")

    download_url = data.get("download_url")
    if not download_url:
        raise HTTPException(status_code=404, detail="Download URL not found.")

    logger.info("Download served for %s by %s", file_id, current_user["email"])
    return {
        "success":      True,
        "download_url": download_url,
        "filename":     data["filename"],
    }


# ── Delete ────────────────────────────────────────────────────────────────────
@router.delete("/delete/{file_id}", status_code=200)
async def delete_file(file_id: str, current_user: dict = Depends(get_current_user)):
    db  = get_db()
    doc = db.collection(FILES_COLLECTION).document(file_id).get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="File not found.")

    data = doc.to_dict()
    uid  = current_user["uid"]
    role = current_user.get("role", "user")

    if data["uid"] != uid and role != "admin":
        raise HTTPException(status_code=403, detail="Access denied.")

    # Delete from Cloudinary
    cloudinary_id = data.get("cloudinary_id")
    if cloudinary_id:
        try:
            cloudinary.uploader.destroy(cloudinary_id, resource_type="raw")
        except Exception as e:
            logger.warning("Cloudinary delete failed for %s: %s", cloudinary_id, str(e))

    # Delete Firestore metadata
    db.collection(FILES_COLLECTION).document(file_id).delete()

    logger.info("File deleted: %s by %s", file_id, current_user["email"])
    return {"success": True, "message": "File deleted."}


# ── Admin: list ALL files ─────────────────────────────────────────────────────
@router.get("/all")
async def list_all_files(admin: dict = Depends(get_current_admin)):
    db   = get_db()
    docs = db.collection(FILES_COLLECTION).order_by("uploaded_at").get()
    return {
        "success": True,
        "files":   [{"id": d.id, **d.to_dict()} for d in docs],
        "count":   len(docs),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────
def _safe_filename(name: str) -> str:
    base = PurePosixPath(name).name
    base = re.sub(r"[^\w.\-]", "_", base)
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{ts}_{base}"


def _increment_storage(uid: str, added_bytes: int) -> int:
    db  = get_db()
    doc = db.collection("users").document(uid).get()
    current = doc.to_dict().get("storage_used_bytes", 0) if doc.exists else 0
    return current + added_bytes