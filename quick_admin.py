"""
Create admin user INSTANTLY - no Flask imports, pure hashlib only.
This avoids any heavy imports that were causing slowness.
"""
import hashlib
import os
import json
import time

# Pure PBKDF2 - no Flask, no config imports
password = "SecurePass@2026"
salt = os.urandom(16)
start = time.time()
derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000, dklen=32)
elapsed = time.time() - start
print(f"PBKDF2 hash created in {elapsed:.3f}s")

# Format: pbkdf2:sha256:1000$<salt_hex>$<hash_hex>
hash_str = f"pbkdf2:sha256:1000${salt.hex()}${derived.hex()}"

# Create users.json
users = {
    "ezaz": {
        "password_hash": hash_str,
        "permissions": "elradfmwMT",
        "created": "2026-01-08T02:20:00"
    }
}

with open("users.json", "w") as f:
    json.dump(users, f, indent=2)

print("users.json CREATED")
print("Admin user: ezaz / SecurePass@2026")
print("DONE!")