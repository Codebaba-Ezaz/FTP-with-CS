import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FTP_ROOT = BASE_DIR / "ftp_root"
UPLOAD_DIR = BASE_DIR / "uploads"
CERT_DIR = BASE_DIR / "certs"

FTP_ROOT.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)
CERT_DIR.mkdir(exist_ok=True)

def get_or_create_secret_key():
    key_file = BASE_DIR / ".secret_key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    try:
        os.chmod(key_file, 0o600)
    except Exception:
        pass
    return key

SECRET_KEY = get_or_create_secret_key()

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = True
PERMANENT_SESSION_LIFETIME = 900

FTP_HOST = "0.0.0.0"
FTP_PORT = 2121
FTP_TLS_PORT = 2122

TLS_CERT_FILE = CERT_DIR / "cert.pem"
TLS_KEY_FILE = CERT_DIR / "key.pem"

FTP_REQUIRE_TLS = True

ADMIN_USER = "ezaz"

PBKDF2_ITERATIONS = 1_000

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 10

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'; "
                                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                                "img-src 'self' data:; "
                                "font-src 'self' https://cdnjs.cloudflare.com;",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store, max-age=0",
}

MAX_CONTENT_LENGTH = 10 * 1024 * 1024

BLOCKED_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js', '.jsp', '.php',
    '.py', '.pl', '.cgi', '.asp', '.aspx', '.jar', '.msi', '.dll', '.so',
    '.dmg', '.pif', '.scr', '.com', '.hta', '.apk', '.app'
}

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
SECURITY_LOG_FILE = LOG_DIR / "security.log"
AUDIT_LOG_FILE = LOG_DIR / "audit.log"