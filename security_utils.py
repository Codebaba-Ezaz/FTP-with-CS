import hashlib
import hmac
import os
import secrets
import time
import logging
import threading
from pathlib import Path
from datetime import datetime
from functools import wraps

from flask import request, session, jsonify, redirect, url_for, flash

import config

class SecurityLogger:
    def __init__(self):
        self._lock = threading.Lock()
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("security")
        self.logger.setLevel(logging.INFO)
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        fh = logging.FileHandler(config.SECURITY_LOG_FILE)
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
        self.audit_logger = logging.getLogger("audit")
        self.audit_logger.setLevel(logging.INFO)
        afh = logging.FileHandler(config.AUDIT_LOG_FILE)
        afh.setFormatter(fmt)
        self.audit_logger.addHandler(afh)

    def _client_ip(self):
        return request.remote_addr if request else "unknown"

    def log_event(self, event, level="INFO"):
        with self._lock:
            self.logger.log(
                getattr(logging, level.upper(), logging.INFO),
                f"{event} | IP={self._client_ip()}"
            )

    def log_audit(self, action, user, details=""):
        with self._lock:
            self.audit_logger.info(
                f"ACTION={action} | USER={user} | DETAILS={details} | IP={self._client_ip()}"
            )

security_log = SecurityLogger()

def hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(16)

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        config.PBKDF2_ITERATIONS,
        dklen=32
    )
    return f"pbkdf2:sha256:{config.PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo_info, salt_hex, hash_hex = stored_hash.split("$")
        _, hash_name, iterations_str = algo_info.split(":")
        iterations = int(iterations_str)

        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)

        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected)
        )
        return hmac.compare_digest(derived, expected)
    except (ValueError, AttributeError):
        return False

class CSRFProtect:
    @staticmethod
    def generate_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    @staticmethod
    def validate_token(token):
        expected = session.get("csrf_token")
        if not expected or not token:
            return False
        return hmac.compare_digest(expected, token)

def csrf_protect(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not CSRFProtect.validate_token(token):
                security_log.log_event(
                    f"CSRF validation FAILED for {request.path}",
                    level="WARNING"
                )
                flash("Security token invalid. Please try again.", "danger")
                return redirect(request.referrer or url_for("list_files"))
        return view_func(*args, **kwargs)
    return wrapper

class LoginAttemptTracker:
    def __init__(self, max_attempts, lockout_seconds):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._attempts = {}
        self._lockouts = {}
        self._lock = threading.Lock()

    def record_failure(self, username):
        with self._lock:
            now = time.time()
            self._attempts.setdefault(username, [])
            self._attempts[username] = [
                t for t in self._attempts[username] if now - t < self.lockout_seconds
            ]
            self._attempts[username].append(now)

            if len(self._attempts[username]) >= self.max_attempts:
                self._lockouts[username] = now + self.lockout_seconds
                security_log.log_event(
                    f"ACCOUNT LOCKED for user '{username}' after "
                    f"{self.max_attempts} failed attempts. Locked for "
                    f"{self.lockout_seconds // 60} minutes.",
                    level="WARNING"
                )
                return True
            return False

    def is_locked(self, username):
        with self._lock:
            lockout_until = self._lockouts.get(username, 0)
            if lockout_until > time.time():
                return True, int(lockout_until - time.time())
            return False, 0

    def reset(self, username):
        with self._lock:
            self._attempts.pop(username, None)
            self._lockouts.pop(username, None)

login_tracker = LoginAttemptTracker(
    config.MAX_LOGIN_ATTEMPTS,
    config.LOCKOUT_DURATION
)

def sanitize_ftp_path(path: str) -> str:
    if not path or not isinstance(path, str):
        return "."

    path = path.replace("\\", "/")

    if path.startswith("/"):
        raise ValueError("Absolute paths are not allowed")
    if ".." in path.split("/"):
        raise ValueError("Path traversal (..) is not allowed")

    cleaned = path.strip()
    while "//" in cleaned:
        cleaned = cleaned.replace("//", "/")
    cleaned = cleaned.strip("/")

    return cleaned if cleaned else "."

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal & special chars.
    """
    # Get just the basename (strip any directory components)
    name = Path(filename).name.replace("\\", "/")
    name = name.split("/")[-1]

    # Remove null bytes and control characters
    name = "".join(c for c in name if c.isprintable() and ord(c) > 31)

    # Block dangerous extensions
    ext = Path(name).suffix.lower()
    if ext in config.BLOCKED_EXTENSIONS:
        raise ValueError(f"File extension '{ext}' is blocked for security reasons.")

    # Reject hidden/system files
    if name.startswith("."):
        raise ValueError("Hidden files cannot be uploaded.")

    return name

# ============================================================
# UPLOAD SIZE VALIDATION
# ============================================================
def validate_upload(file_storage) -> bool:
    """Validate an uploaded file: size, extension, content-type."""
    if not file_storage:
        return False

    try:
        clean_name = sanitize_filename(file_storage.filename)
    except ValueError:
        return False

    # Check content length (Flask also enforces MAX_CONTENT_LENGTH globally)
    file_storage.seek(0, 2)
    size = file_storage.tell()
    file_storage.seek(0)

    if size > config.MAX_CONTENT_LENGTH:
        return False

    return True

# ============================================================
# LOGIN REQUIRED DECORATOR
# ============================================================
def login_required(func):
    """Ensure only authenticated, logged-in users can access the view.

    Any user present in user_db.py (not just config.ADMIN_USER) is
    accepted here, since the whole point of user_db is to support
    multiple accounts. If you need admin-only routes later, add a
    separate `admin_required` decorator instead of overloading this one.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            security_log.log_event(
                f"UNAUTHORIZED access attempt to {request.path}",
                level="WARNING"
            )
            flash("Please login to access this feature.", "warning")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

# ============================================================
# SECURITY HEADERS MIDDLEWARE
# ============================================================
def apply_security_headers(response):
    """Add HTTP security headers to every response."""
    for header, value in config.SECURITY_HEADERS.items():
        response.headers[header] = value
    return response