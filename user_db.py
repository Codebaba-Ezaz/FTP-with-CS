
import json
import threading
from pathlib import Path

import config
from security_utils import hash_password, verify_password

USER_DB_FILE = config.BASE_DIR / "users.json"


class UserDB:
    def __init__(self, db_file: Path):
        self.db_file = db_file
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if self.db_file.exists():
            try:
                with open(self.db_file, "r", encoding="utf-8") as f:
                    self._users = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._users = {}
        else:
            self._users = {}

    def _save(self):
        with self._lock:
            try:
                with open(self.db_file, "w", encoding="utf-8") as f:
                    json.dump(self._users, f, indent=2)
                    f.flush()
                try:
                    import os
                    os.chmod(self.db_file, 0o600)
                except Exception:
                    pass
            except OSError as e:
                import logging
                logging.getLogger("security").error(f"Failed to save user database: {e}")

    def add_user(self, username: str, password: str, permissions: str = "elradfmwMT"):
        with self._lock:
            self._users[username] = {
                "password_hash": hash_password(password),
                "permissions": permissions,
                "created": __import__("datetime").datetime.now().isoformat()
            }
            self._save()

    def verify_credentials(self, username: str, password: str) -> bool:
        user = self._users.get(username)
        if not user:
            return False
        return verify_password(password, user.get("password_hash", ""))

    def change_password(self, username: str, new_password: str) -> bool:
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
        user = self._users.get(username)
        if user:
            safe = dict(user)
            safe.pop("password_hash", None)
            return safe
        return None

    def list_users(self):
        return list(self._users.keys())

    def user_exists(self, username: str) -> bool:
        return username in self._users

    def reload(self):
        with self._lock:
            self._load()

    def delete_user(self, username: str) -> bool:
        with self._lock:
            if username in self._users:
                del self._users[username]
                self._save()
                return True
            return False


user_db = UserDB(USER_DB_FILE)