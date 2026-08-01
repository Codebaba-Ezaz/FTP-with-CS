import sys
import os
import time

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

user_db.add_user(config.ADMIN_USER, "SecurePass@2026")

elapsed = time.time() - start
print()
print(f"[OK] Admin user '{config.ADMIN_USER}' created in {elapsed:.2f}s")
print()

import json
with open("users.json", "r") as f:
    data = json.load(f)
stored_hash = data[config.ADMIN_USER]["password_hash"]
print(f"    Stored hash (NOT the password!):")
print(f"    {stored_hash[:70]}...")
print(f"    → Plaintext password is NEVER stored")
print()

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
print("  1) python ftp_server.py     (plain FTP on port 2121)")
print("  2) python -c \"import config; config.FTP_REQUIRE_TLS=True; import ftp_server; ftp_server.main()\"")
print("     (FTPS on port 2122)")
print("  3) python web_frontend.py   (Web UI on port 5000)")
print("  4) Open http://localhost:5000")
print("=" * 60)