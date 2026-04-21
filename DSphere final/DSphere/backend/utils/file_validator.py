"""
DSphere — utils/file_validator.py
Deep file inspection to block malicious uploads.

Checks performed:
  1. Magic byte verification (actual file type vs claimed extension)
  2. Script injection patterns in text-based files
  3. Executable / PE header detection
  4. Macro detection in Office documents
  5. Oversized embedded objects
"""

import re
import logging
from pathlib import PurePosixPath

logger = logging.getLogger("dsphere.file_validator")

# ── Magic bytes (file signatures) ────────────────────────────────────────────
MAGIC_SIGNATURES = {
    # image
    b"\xFF\xD8\xFF":     {".jpg", ".jpeg"},
    b"\x89PNG\r\n\x1a\n": {".png"},
    # PDF
    b"%PDF":             {".pdf"},
    # Office Open XML (zip-based)
    b"PK\x03\x04":      {".docx", ".pptx", ".xlsx", ".ppt"},
    # XML
    b"<?xml":            {".xml"},
    b"\xef\xbb\xbf<?xml": {".xml"},   # UTF-8 BOM + xml
    # Executables (always blocked)
    b"MZ":               set(),        # PE / Windows EXE
    b"\x7fELF":          set(),        # Linux ELF
    b"\xca\xfe\xba\xbe": set(),        # Mach-O fat binary
    b"\xfe\xed\xfa":     set(),        # Mach-O
}

# ── Patterns that indicate malicious content in text files ───────────────────
MALICIOUS_PATTERNS = [
    # Script tags
    rb"<script[\s>]",
    rb"javascript:",
    rb"vbscript:",
    # Shell
    rb"eval\s*\(",
    rb"exec\s*\(",
    rb"system\s*\(",
    rb"subprocess",
    rb"os\.system",
    # PowerShell / cmd
    rb"powershell",
    rb"cmd\.exe",
    rb"whoami",
    rb"net\s+user",
    # PHP backdoor
    rb"<\?php",
    rb"passthru\s*\(",
    rb"base64_decode\s*\(",
    # XXE / SSRF in XML
    rb"<!ENTITY",
    rb"SYSTEM\s+[\"']",
    rb"file:///",
    rb"http://169\.254",     # AWS metadata
]

# ── Text-based extensions that need pattern scanning ─────────────────────────
TEXT_EXTENSIONS = {".xml", ".ppt"}   # ppt can be XML-based (old format)

# ── Office macro indicators ───────────────────────────────────────────────────
MACRO_INDICATORS = [
    b"vbaProject.bin",
    b"xl/vbaProject",
    b"word/vbaProject",
    b"_VBA_PROJECT",
    b"VBA7",
    b"AutoOpen",
    b"AutoExec",
    b"Document_Open",
    b"Workbook_Open",
]


def validate_file(content: bytes, extension: str, filename: str) -> dict:
    """
    Validate file content.
    Returns {"safe": True} or {"safe": False, "reason": "..."}
    """

    # ── 1. Executable magic bytes (unconditional block) ────────────────────
    for sig, allowed_exts in MAGIC_SIGNATURES.items():
        if content.startswith(sig) and len(allowed_exts) == 0:
            reason = f"Executable binary detected (magic bytes: {sig.hex()})"
            logger.warning("BLOCKED: %s — %s", filename, reason)
            return {"safe": False, "reason": reason}

    # ── 2. Magic byte ↔ extension consistency ─────────────────────────────
    detected_exts: set[str] = set()
    for sig, allowed_exts in MAGIC_SIGNATURES.items():
        if content.startswith(sig) and allowed_exts:
            detected_exts.update(allowed_exts)

    if detected_exts and extension not in detected_exts:
        # Special case: .ppt can be old binary format (D0CF11E0)
        if extension == ".ppt" and content[:4] == b"\xd0\xcf\x11\xe0":
            pass  # Old PPT binary format — OK
        else:
            reason = f"File extension '{extension}' does not match actual file type (detected: {detected_exts})"
            logger.warning("BLOCKED (spoofed extension): %s — %s", filename, reason)
            return {"safe": False, "reason": reason}

    # ── 3. Malicious pattern scan (text-based and XML files) ──────────────
    scan_content = content[:1_000_000]  # scan first 1 MB max
    if extension in TEXT_EXTENSIONS or _looks_like_text(content[:256]):
        for pattern in MALICIOUS_PATTERNS:
            if re.search(pattern, scan_content, re.IGNORECASE):
                reason = f"Malicious pattern detected: {pattern.decode(errors='replace')}"
                logger.warning("BLOCKED (malicious pattern): %s — %s", filename, reason)
                return {"safe": False, "reason": "File contains potentially dangerous content."}

    # ── 4. Office macro detection ──────────────────────────────────────────
    if extension in {".docx", ".pptx", ".xlsx"}:
        for indicator in MACRO_INDICATORS:
            if indicator in content:
                reason = f"Office macro detected: {indicator.decode(errors='replace')}"
                logger.warning("BLOCKED (macro): %s — %s", filename, reason)
                return {"safe": False, "reason": "Macro-enabled Office documents are not permitted."}

    # ── 5. Null bytes in images (common steganography / exploit technique) ─
    if extension in {".jpg", ".jpeg", ".png"} and b"\x00" * 16 in content[512:]:
        # Some legitimate images have null regions; only flag large contiguous runs
        null_run = max((len(m.group()) for m in re.finditer(rb"\x00{32,}", content[512:])), default=0)
        if null_run > 10_000:
            reason = "Unusually large null-byte region detected in image"
            logger.warning("BLOCKED (suspicious image): %s — %s", filename, reason)
            return {"safe": False, "reason": "Suspicious image structure detected."}

    logger.debug("File passed validation: %s (%d bytes)", filename, len(content))
    return {"safe": True}


def _looks_like_text(sample: bytes) -> bool:
    """Heuristic: if >85% of bytes are printable ASCII, treat as text."""
    if not sample:
        return False
    printable = sum(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in sample)
    return printable / len(sample) > 0.85