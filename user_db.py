"""
User Database Module
--------------------
Stores user credentials SECURELY:
- Passwords are stored as PBKDF2 hashes, NEVER plaintext
- Uses HMAC-SHA256 via hashlib.pbkdf2_hmac
- This demonstrates the "Password Storage" concept from Computer Security
"""

import json
import threading
from pathlib import Path

import config
from security_utils import hash_password, verify_password

# ============================================================
# USER DATABASE FILE
# ============================================================
USER_DB_FILE = config.BASE_DIR / "users.json"


class UserDB:
    """
    A small JSON-based user store.
    In a real production system you'd use a proper database with
    additional protections (encryption at rest, access controls).
    
    SECURITY FEATURES:
    - Passwords stored as PBKDF2 hashes + salt (never plaintext)
    - File permission restricted on POSIX systems
    - Thread-safe reads/writes
    """

    def __init__(self, db_file: Path):
        self.db_file = db_file
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        """Load users from disk (or create empty DB)."""
        if self.db_file.exists():
            try:
                with open(self.db_file, "r", encoding="utf-8") as f:
                    self._users = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._users = {}
        else:
            self._users = {}

    def _save(self):
        """Persist users to disk with restricted permissions."""
        with self._lock:
            try:
                with open(self.db_file, "w", encoding="utf-8") as f:
                    json.dump(self._users, f, indent=2)
                    f.flush()
                # Restrict permissions (POSIX only; best-effort on Windows)
                try:
                    import os
                    os.chmod(self.db_file, 0o600)
                except Exception:
                    pass
            except OSError as e:
                # Log the error but don't crash — the in-memory data is still valid
                import logging
                logging.getLogger("security").error(f"Failed to save user database: {e}")

    def add_user(self, username: str, password: str, permissions: str = "elradfmwMT"):
        """
        Add a new user.
        The PLAINTEXT password is converted to a PBKDF2 hash immediately.
        The plaintext is NEVER stored or logged.
        """
        with self._lock:
            self._users[username] = {
                "password_hash": hash_password(password),  # PBKDF2-HMAC-SHA256
                "permissions": permissions,
                "created": __import__("datetime").datetime.now().isoformat()
            }
            self._save()

    def verify_credentials(self, username: str, password: str) -> bool:
        """
        Verify username + password.
        Uses constant-time comparison internally (timing-attack safe).
        """
        user = self._users.get(username)
        if not user:
            return False
        return verify_password(password, user.get("password_hash", ""))

    def change_password(self, username: str, new_password: str) -> bool:
        """Securely change a user's password (re-hash with fresh salt)."""
        with self._lock:
            if username not in self._users:
                return False
            self._users[username]["password_hash"] = hash_password(new_password)
            self._users[username]["last_changed"] = (
                __import__("datetime").datetime.now().isoformat()
            )
            self._save()
            return True

    def get_user(self, username: str):
        """Get a user record (does NOT expose the password hash)."""
        user = self._users.get(username)
        if user:
            # Return a copy without the sensitive hash
            safe = dict(user)
            safe.pop("password_hash", None)
            return safe
        return None

    def list_users(self):
        """List usernames (no sensitive data)."""
        return list(self._users.keys())

    def user_exists(self, username: str) -> bool:
        return username in self._users

    def reload(self):
        """Reload users from disk. Useful when another process modifies users.json."""
        with self._lock:
            self._load()

    def delete_user(self, username: str) -> bool:
        """Delete a user from the database. Returns True if deleted, False if not found."""
        with self._lock:
            if username in self._users:
                del self._users[username]
                self._save()
                return True
            return False


# ============================================================
# SINGLETON INSTANCE
# ============================================================
# Global user database instance
user_db = UserDB(USER_DB_FILE)
