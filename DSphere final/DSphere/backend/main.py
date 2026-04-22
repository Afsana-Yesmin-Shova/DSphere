"""
DSphere — main.py
FastAPI application entry point.
Deploy on Render / Railway via:  uvicorn main:app --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

from config import settings
from middleware.threat_detection import ThreatDetectionMiddleware
from middleware.rate_limiter import setup_rate_limiter
from routes import auth, storage, network, admin

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("dsphere")

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="DSphere API",
    description="Secure university cloud backend — Uttara University",
    version="1.0.0",
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url=None,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    settings.FRONTEND_URL,
    "https://dspheree.netlify.app",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Custom Middleware ─────────────────────────────────────────────────────────
app.add_middleware(ThreatDetectionMiddleware)

# ── Rate Limiter (SlowAPI) ────────────────────────────────────────────────────
limiter = setup_rate_limiter(app)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router,    prefix="/auth",    tags=["Authentication"])
app.include_router(storage.router, prefix="/storage", tags=["Cloud Storage"])
app.include_router(network.router, prefix="/network", tags=["Network Suggestor"])
app.include_router(admin.router,   prefix="/admin",   tags=["Admin"])

# ── Global Exception Handler ──────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": "An internal server error occurred."},
    )

# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "ok", "service": "DSphere API", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
