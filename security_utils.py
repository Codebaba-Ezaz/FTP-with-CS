"""
Security Utilities Module
-------------------------
Implements core Computer Security concepts:
1. Password Hashing (PBKDF2) - "Password Storage"
2. CSRF Token Protection - "Request Forgery Defense"
3. Rate Limiting / Account Lockout - "Brute Force Defense"
4. Audit Logging - "Accountability & Non-Repudiation"
5. Path Traversal Prevention - "Input Validation"
"""

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

# ============================================================
# AUDIT LOGGING
# ============================================================
# "Accountability" - every sensitive action must be recorded.
class SecurityLogger:
    """Dual-channel logger: general security log + detailed audit log."""

    def __init__(self):
        self._lock = threading.Lock()
        self._setup_logger()

    def _setup_logger(self):
        self.logger = logging.getLogger("security")
        self.logger.setLevel(logging.INFO)
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )
        # Security log file
        fh = logging.FileHandler(config.SECURITY_LOG_FILE)
        fh.setFormatter(fmt)
        self.logger.addHandler(fh)
        # Audit log file
        self.audit_logger = logging.getLogger("audit")
        self.audit_logger.setLevel(logging.INFO)
        afh = logging.FileHandler(config.AUDIT_LOG_FILE)
        afh.setFormatter(fmt)
        self.audit_logger.addHandler(afh)

    def _client_ip(self):
        """Get the real client IP (handles proxies)."""
        # X-Forwarded-For is set by reverse proxies. 
        # NOTE: Only trust it if behind a trusted proxy!
        # For this lab, we use direct IP.
        return request.remote_addr if request else "unknown"

    def log_event(self, event, level="INFO"):
        """Log a security event with caller context."""
        with self._lock:
            self.logger.log(
                getattr(logging, level.upper(), logging.INFO),
                f"{event} | IP={self._client_ip()}"
            )

    def log_audit(self, action, user, details=""):
        """Create a detailed audit trail entry (non-repudiation)."""
        with self._lock:
            self.audit_logger.info(
                f"ACTION={action} | USER={user} | DETAILS={details} | IP={self._client_ip()}"
            )

security_log = SecurityLogger()

# ============================================================
# PASSWORD HASHING (PBKDF2)
# ============================================================
def hash_password(password: str, salt: bytes | None = None) -> str:
    """
    Hash a password using PBKDF2-HMAC-SHA256.
    Returns: "pbkdf2:sha256:ITERATIONS$SALT_HEX$HASH_HEX"
    
    Why PBKDF2?
    - Salt prevents rainbow table attacks (unique per password)
    - Iterations slow down brute-force attacks significantly
    - One-way hash means password can never be recovered from DB
    """
    if salt is None:
        # 16 bytes of cryptographic randomness
        salt = os.urandom(16)

    # PBKDF2 derives a fixed-length key from the password + salt
    # via iterated HMAC. 600k iterations ≈ ~0.3 seconds per attempt,
    # making offline brute-force extremely expensive.
    derived = hashlib.pbkdf2_hmac(
        "sha256",                     # hash algorithm
        password.encode("utf-8"),    # password bytes
        salt,                         # random salt
        config.PBKDF2_ITERATIONS,     # cost factor
        dklen=32                      # 256-bit output
    )
    return f"pbkdf2:sha256:{config.PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a password against the stored PBKDF2 hash.
    Uses hmac.compare_digest for CONSTANT-TIME comparison
    to prevent TIMING ATTACKS.
    """
    try:
        # Format: "pbkdf2:sha256:ITERATIONS$SALT_HEX$HASH_HEX"
        algo_info, salt_hex, hash_hex = stored_hash.split("$")
        _, hash_name, iterations_str = algo_info.split(":")
        iterations = int(iterations_str)

        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)

        derived = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected)
        )
        # hmac.compare_digest = constant-time compare (no timing leaks)
        return hmac.compare_digest(derived, expected)
    except (ValueError, AttributeError):
        return False

# ============================================================
# CSRF PROTECTION
# ============================================================
class CSRFProtect:
    """Generate and validate CSRF tokens to prevent Cross-Site Request Forgery."""

    @staticmethod
    def generate_token():
        """Generate a fresh CSRF token and store it in the session."""
        if "csrf_token" not in session:
            # secrets.token_urlsafe(32) => 32 random bytes, URL-safe base64
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    @staticmethod
    def validate_token(token):
        """Validate the submitted token against the session token."""
        expected = session.get("csrf_token")
        if not expected or not token:
            return False
        # constant-time comparison to prevent timing attacks
        return hmac.compare_digest(expected, token)

def csrf_protect(view_func):
    """Decorator: require valid CSRF token for state-changing requests (POST)."""
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

# ============================================================
# RATE LIMITING / ACCOUNT LOCKOUT
# ============================================================
class LoginAttemptTracker:
    """
    Protects against Brute-Force attacks.
    After N failed attempts, the account is locked for X seconds.
    Uses in-memory dict keyed by username (per-process).
    In production you'd use Redis for distributed locking.
    """

    def __init__(self, max_attempts, lockout_seconds):
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._attempts = {}          # username -> list of attempt timestamps
        self._lockouts = {}          # username -> lockout_until_epoch
        self._lock = threading.Lock()

    def record_failure(self, username):
        """Record a failed login attempt and apply lockout if threshold reached."""
        with self._lock:
            now = time.time()
            # Clean old attempts
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
        """Check if an account is currently locked out."""
        with self._lock:
            lockout_until = self._lockouts.get(username, 0)
            if lockout_until > time.time():
                return True, int(lockout_until - time.time())
            return False, 0

    def reset(self, username):
        """Reset attempts after a successful login."""
        with self._lock:
            self._attempts.pop(username, None)
            self._lockouts.pop(username, None)

# Singleton instance
login_tracker = LoginAttemptTracker(
    config.MAX_LOGIN_ATTEMPTS,
    config.LOCKOUT_DURATION
)

# ============================================================
# PATH TRAVERSAL PREVENTION
# ============================================================
def sanitize_ftp_path(path: str) -> str:
    """
    Prevent Path Traversal attacks.
    - Block absolute paths
    - Block '..' components
    - Normalize to use forward slashes
    """
    if not path or not isinstance(path, str):
        return "."

    # Replace backslashes (Windows) with forward slashes
    path = path.replace("\\", "/")

    # Reject absolute paths and traversal
    if path.startswith("/"):
        raise ValueError("Absolute paths are not allowed")
    if ".." in path.split("/"):
        raise ValueError("Path traversal (..) is not allowed")

    # Remove leading ./ and duplicate slashes
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
    """Ensure only authenticated admin users can access the view."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "username" not in session or session.get("username") != config.ADMIN_USER:
            security_log.log_event(
                f"UNAUTHORIZED access attempt to {request.path}",
                level="WARNING"
            )
            flash("Please login as admin to access this feature.", "warning")
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