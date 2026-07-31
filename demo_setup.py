"""
SECURE DEMO - Create Admin User
===============================
This demonstrates PBKDF2 password hashing.
PBKDF2 is deliberately slow (~10 seconds on this CPU) so that
brute-force password cracking becomes IMPRACTICAL.

Watch what happens:
1. You enter a password
2. PBKDF2 hashes it with 20,000,000 iterations
3. It takes ~10 seconds (this is SECURITY, not a bug!)
4. Only the hash is stored - never the plaintext

Run:  python demo_setup.py
"""

import sys
import os
import time

# Make sure we use the project's modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from user_db import user_db

print("=" * 60)
print("  SECURE FTP PROJECT - ADMIN SETUP")
print("=" * 60)
print()
print(f"[1] PBKDF2-HMAC-SHA256 Password Hashing")
print(f"    Iterations: {config.PBKDF2_ITERATIONS:,}")
print(f"    Each hash takes ~10 seconds on this CPU")
print()
print(f"[2] Creating admin user: '{config.ADMIN_USER}'")
print()
print(f"[*] Hashing password with PBKDF2...")
print(f"    ⏳ Please wait ~10 seconds")
print(f"    (This delay IS the security - it makes brute-force")
print(f"     password cracking take years instead of seconds)")
print()

start = time.time()

# THE DEMO MOMENT!
# user_db.add_user() internally uses hash_password() which runs PBKDF2
# with 20,000,000 iterations. This takes ~10 seconds.
user_db.add_user(config.ADMIN_USER, "SecurePass@2026")

elapsed = time.time() - start
print()
print(f"[OK] Admin user '{config.ADMIN_USER}' created in {elapsed:.2f}s")
print()

# Show the stored hash (from users.json)
import json
with open("users.json", "r") as f:
    data = json.load(f)
stored_hash = data[config.ADMIN_USER]["password_hash"]
print(f"    Stored hash (NOT the password!):")
print(f"    {stored_hash[:70]}...")
print(f"    → Plaintext password is NEVER stored")
print()

# Verify login works
print(f"[3] Verifying login (another ~10s PBKDF2 round)...")
start = time.time()
verified = user_db.verify_credentials(config.ADMIN_USER, "SecurePass@2026")
elapsed = time.time() - start
print(f"[OK] Login verified in {elapsed:.2f}s: {'SUCCESS' if verified else 'FAILED'}")
print()

print("=" * 60)
print("  LOGIN CREDENTIALS FOR DEMO:")
print(f"  Username: {config.ADMIN_USER}")
print(f"  Password: SecurePass@2026")
print()
print("  To run the app:")
print("  1) python ftp_server.py     (FTPS server on port 2121)")
print("  2) python web_frontend.py   (Web UI on port 5000)")
print("  3) Open http://localhost:5000")
print("=" * 60)