"""
DSphere — tests/test_routes.py
Smoke tests covering auth, storage, network, and admin routes.
Run with: pytest tests/ -v

Note: These are integration smoke tests.
      Set TEST_* env vars or use a .env.test file before running.
      Firebase calls are mocked so no real Firestore writes occur.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Patch firebase before importing app
with patch("firebase_admin.initialize_app"), \
     patch("firebase_admin.credentials.Certificate"), \
     patch("firebase_admin.firestore.client"), \
     patch("firebase_admin.storage.bucket"):
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from main import app

client = TestClient(app)

# ── fixtures ──────────────────────────────────────────────────
VALID_EMAIL   = "test.user@uttarauniversity.edu.bd"
INVALID_EMAIL = "test.user@gmail.com"
STRONG_PW     = "Secure@123"
WEAK_PW       = "password"


# ── health check ──────────────────────────────────────────────
def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── AUTH: register ────────────────────────────────────────────
class TestRegister:
    def test_invalid_email_domain(self):
        r = client.post("/auth/register", json={
            "name": "Alice", "email": INVALID_EMAIL, "password": STRONG_PW
        })
        assert r.status_code == 422

    def test_weak_password(self):
        r = client.post("/auth/register", json={
            "name": "Alice", "email": VALID_EMAIL, "password": WEAK_PW
        })
        assert r.status_code == 422

    @patch("routes.auth._get_user_by_email", return_value=None)
    @patch("routes.auth.pwd_ctx.hash", return_value="hashed")
    @patch("routes.auth.generate_otp", return_value="123456")
    @patch("routes.auth.store_otp")
    @patch("routes.auth.send_otp_email", return_value=True)
    @patch("firebase_admin_init.get_db")
    def test_valid_registration(self, mock_db, mock_send, mock_store, mock_otp, mock_hash, mock_get):
        mock_doc_ref = MagicMock()
        mock_db.return_value.collection.return_value.document.return_value = mock_doc_ref
        r = client.post("/auth/register", json={
            "name": "Alice", "email": VALID_EMAIL, "password": STRONG_PW
        })
        assert r.status_code == 201
        assert r.json()["success"] is True


# ── AUTH: login ───────────────────────────────────────────────
class TestLogin:
    def test_invalid_email_domain(self):
        r = client.post("/auth/login", json={"email": INVALID_EMAIL, "password": STRONG_PW})
        assert r.status_code == 422

    def test_user_not_found(self):
        with patch("routes.auth._get_user_by_email", return_value=None):
            r = client.post("/auth/login", json={"email": VALID_EMAIL, "password": STRONG_PW})
        assert r.status_code == 401

    @patch("routes.auth._get_user_by_email", return_value={
        "id": "uid123", "email": VALID_EMAIL, "name": "Alice",
        "role": "user", "verified": True, "active": True, "password_hash": "hashed"
    })
    @patch("routes.auth.pwd_ctx.verify", return_value=True)
    @patch("middleware.rate_limiter.brute_force.is_blocked", return_value=False)
    @patch("middleware.rate_limiter.brute_force.record_success")
    def test_successful_login(self, mock_success, mock_blocked, mock_verify, mock_user):
        r = client.post("/auth/login", json={"email": VALID_EMAIL, "password": STRONG_PW})
        assert r.status_code == 200
        assert "access_token" in r.json()

    @patch("routes.auth._get_user_by_email", return_value={
        "id": "uid123", "email": VALID_EMAIL, "name": "Alice",
        "role": "user", "verified": False, "active": True, "password_hash": "hashed"
    })
    @patch("middleware.rate_limiter.brute_force.is_blocked", return_value=False)
    def test_unverified_user(self, mock_blocked, mock_user):
        r = client.post("/auth/login", json={"email": VALID_EMAIL, "password": STRONG_PW})
        assert r.status_code == 403


# ── NETWORK: subnet calculator ────────────────────────────────
class TestNetwork:
    def _auth_headers(self):
        from utils.jwt_handler import create_access_token
        token = create_access_token({"uid": "uid1", "email": VALID_EMAIL, "role": "user"})
        return {"Authorization": f"Bearer {token}"}

    def test_invalid_device_count(self):
        r = client.post("/network/suggest",
            json={"device_count": 0, "purpose": "office"},
            headers=self._auth_headers())
        assert r.status_code == 422

    def test_classroom_subnet(self):
        r = client.post("/network/suggest",
            json={"device_count": 30, "purpose": "classroom lab"},
            headers=self._auth_headers())
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert "subnet" in data
        assert data["subnet"]["usable_hosts"] >= 30
        assert data["topology"]["primary"]["type"] == "LAN"

    def test_campus_topology(self):
        r = client.post("/network/suggest",
            json={"device_count": 500, "purpose": "university campus"},
            headers=self._auth_headers())
        assert r.status_code == 200
        data = r.json()
        assert data["topology"]["primary"]["type"] in ("MAN", "LAN")

    def test_large_network(self):
        r = client.post("/network/suggest",
            json={"device_count": 5000, "purpose": "city municipality"},
            headers=self._auth_headers())
        assert r.status_code == 200
        assert r.json()["topology"]["primary"]["type"] == "MAN"

    def test_topologies_list(self):
        r = client.get("/network/topologies", headers=self._auth_headers())
        assert r.status_code == 200
        assert len(r.json()["topologies"]) >= 5


# ── FILE VALIDATOR unit tests ─────────────────────────────────
class TestFileValidator:
    def test_safe_pdf(self):
        from utils.file_validator import validate_file
        content = b"%PDF-1.4 simple pdf content"
        result = validate_file(content, ".pdf", "test.pdf")
        assert result["safe"] is True

    def test_exe_blocked(self):
        from utils.file_validator import validate_file
        content = b"MZ\x90\x00" + b"\x00" * 100   # PE header
        result = validate_file(content, ".exe", "malware.exe")
        assert result["safe"] is False

    def test_script_injection_in_xml(self):
        from utils.file_validator import validate_file
        content = b"<?xml version='1.0'?><root><script>eval('bad')</script></root>"
        result = validate_file(content, ".xml", "payload.xml")
        assert result["safe"] is False

    def test_macro_in_docx(self):
        from utils.file_validator import validate_file
        content = b"PK\x03\x04" + b"vbaProject.bin" + b"\x00" * 50
        result = validate_file(content, ".docx", "macro.docx")
        assert result["safe"] is False

    def test_extension_spoof(self):
        from utils.file_validator import validate_file
        # PNG header but .pdf extension
        content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        result = validate_file(content, ".pdf", "image_renamed.pdf")
        assert result["safe"] is False


# ── BRUTE FORCE unit tests ────────────────────────────────────
class TestBruteForce:
    def setup_method(self):
        from middleware.rate_limiter import _attempts
        _attempts.clear()

    def test_warning_at_3_attempts(self):
        from middleware.rate_limiter import brute_force
        ip = "10.0.0.1"
        for _ in range(3):
            result = brute_force.record_failure(ip, "test@uttarauniversity.edu.bd")
        assert result["warned"] is True
        assert result["blocked"] is False

    def test_block_at_5_attempts(self):
        from middleware.rate_limiter import brute_force
        ip = "10.0.0.2"
        result = None
        for _ in range(5):
            result = brute_force.record_failure(ip, "test@uttarauniversity.edu.bd")
        assert result["blocked"] is True
        assert brute_force.is_blocked(ip) is True

    def test_success_clears_counter(self):
        from middleware.rate_limiter import brute_force
        ip = "10.0.0.3"
        brute_force.record_failure(ip, "test@uttarauniversity.edu.bd")
        brute_force.record_success(ip)
        assert brute_force.is_blocked(ip) is False

    def test_manual_block_unblock(self):
        from middleware.rate_limiter import brute_force
        ip = "10.0.0.4"
        brute_force.manual_block(ip, minutes=60)
        assert brute_force.is_blocked(ip) is True
        brute_force.manual_unblock(ip)
        assert brute_force.is_blocked(ip) is False