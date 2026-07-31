"""
Security Configuration Module
-----------------------------
Centralized place for all security-related settings.
This is a core concept in Computer Security: 
"Security by Centralization / Separation of Duties"
"""

import os
import secrets
from pathlib import Path

# ============================================================
# BASE PATHS
# ============================================================
BASE_DIR = Path(__file__).resolve().parent
FTP_ROOT = BASE_DIR / "ftp_root"
UPLOAD_DIR = BASE_DIR / "uploads"
CERT_DIR = BASE_DIR / "certs"

# Create directories if they don't exist
FTP_ROOT.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
CERT_DIR.mkdir(exist_ok=True)

# ============================================================
# FLASK SESSION SECURITY
# ============================================================
# GOOD: Generate a strong random secret key.
# Never hardcode it in source code (it would be in git history / source control).
# In this lab we generate one and save it to a file on first run,
# so it stays OUT of the source code.
def get_or_create_secret_key():
    """Load secret key from file, or generate + save a cryptographically secure one."""
    key_file = BASE_DIR / ".secret_key"
    if key_file.exists():
        return key_file.read_text().strip()
    # secrets.token_hex(32) => 64 hex chars = 256 bits of entropy (cryptographically secure)
    key = secrets.token_hex(32)
    key_file.write_text(key)
    # Restrict permissions on Windows-compatible way (best effort)
    try:
        os.chmod(key_file, 0o600)
    except Exception:
        pass  # Windows doesn't fully support chmod, but ignore
    return key

SECRET_KEY = get_or_create_secret_key()

# ============================================================
# WEB SESSION SETTINGS (Flask)
# ============================================================
SESSION_COOKIE_HTTPONLY = True      # Prevent JavaScript from reading session cookie (XSS protection)
SESSION_COOKIE_SAMESITE = 'Lax'     # Mitigate CSRF at browser level
SESSION_COOKIE_SECURE = True        # Only send cookie over HTTPS
PERMANENT_SESSION_LIFETIME = 900    # Session expires after 15 minutes (minimize session hijacking window)

# ============================================================
# FTP / FTPS SETTINGS
# ============================================================
FTP_HOST = "0.0.0.0"
FTP_PORT = 2121

# TLS certificate paths (generate with generate_cert.py)
TLS_CERT_FILE = CERT_DIR / "cert.pem"
TLS_KEY_FILE = CERT_DIR / "key.pem"

# When True, FTP requires TLS (like FTPS with AUTH TLS)
# This ensures credentials are NOT sent in plaintext over the network.
FTP_REQUIRE_TLS = True

# ============================================================
# AUTHENTICATION SETTINGS
# ============================================================
# ADMIN_USER is the only allowed login. Stored hashed (PBKDF2-SHA256), NEVER plaintext.
ADMIN_USER = "ezaz"

# PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA256.
# Iterations = time cost factor — higher = harder for brute-force attacks.
# For lab demo: 1,000 iterations = instant (fast for demo/showcase).
# (The security concept is still demonstrated: password is hashed with
#  salt + iterated HMAC - never stored as plaintext.)
PBKDF2_ITERATIONS = 1_000

# ============================================================
# BRUTE-FORCE / RATE LIMITING
# ============================================================
# Account lockout after N failed attempts
MAX_LOGIN_ATTEMPTS = 5
# Lockout duration in seconds (15 minutes)
LOCKOUT_DURATION = 900

# ============================================================
# SECURITY HEADERS (HTTP response headers)
# ============================================================
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",          # Prevent MIME-type sniffing
    "X-Frame-Options": "DENY",                     # Prevent clickjacking (frame embedding)
    "X-XSS-Protection": "1; mode=block",           # Browser XSS filter
    "Referrer-Policy": "strict-origin-when-cross-origin",  # Limit referrer leakage
    "Content-Security-Policy": "default-src 'self'; "
                                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                                "img-src 'self' data:; "
                                "font-src 'self' https://cdnjs.cloudflare.com;",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store, max-age=0",        # Don't cache sensitive pages
}

# ============================================================
# FILE UPLOAD SECURITY
# ============================================================
# Maximum upload size (10 MB)
MAX_CONTENT_LENGTH = 10 * 1024 * 1024

# Dangerous file extensions to block (executable / script files)
BLOCKED_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js', '.jsp', '.php',
    '.py', '.pl', '.cgi', '.asp', '.aspx', '.jar', '.msi', '.dll', '.so',
    '.dmg', '.pif', '.scr', '.com', '.hta', '.apk', '.app'
}

# ============================================================
# LOGGING / AUDIT
# ============================================================
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
SECURITY_LOG_FILE = LOG_DIR / "security.log"
AUDIT_LOG_FILE = LOG_DIR / "audit.log"