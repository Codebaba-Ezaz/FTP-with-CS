"""
Quick verification of all security modules.
"""
import sys
import os

print("=" * 60)
print("SECURE FTP PROJECT - VERIFICATION")
print("=" * 60)

# 1. Verify config
try:
    import config
    print(f"[OK] config.py loaded")
    print(f"     Secret Key: {'*' * 10 + config.SECRET_KEY[-4:]}")
    print(f"     FTP Port: {config.FTP_PORT}")
    print(f"     FTPS Port: {config.FTP_TLS_PORT}")
    print(f"     Max Attempts: {config.MAX_LOGIN_ATTEMPTS}")
    print(f"     Lockout: {config.LOCKOUT_DURATION} seconds")
except Exception as e:
    print(f"[FAIL] config.py: {e}")

# 2. Verify security_utils
try:
    from security_utils import hash_password, verify_password
    from security_utils import sanitize_ftp_path, sanitize_filename
    from security_utils import CSRFProtect, login_tracker
    print(f"[OK] security_utils.py loaded")
    
    # Test hashing
    h = hash_password("testpw123")
    assert verify_password("testpw123", h), "Password verification failed"
    print(f"     PBKDF2 password hashing: WORKING")
    print(f"     Sample hash: {h[:40]}...")
except Exception as e:
    print(f"[FAIL] security_utils.py: {e}")

# 3. Verify user_db
try:
    from user_db import user_db
    print(f"[OK] user_db.py loaded")
    print(f"     DB file: {user_db.db_file}")
    print(f"     Existing users: {user_db.list_users()}")
except Exception as e:
    print(f"[FAIL] user_db.py: {e}")

# 4. Verify ftp_server
try:
    import ftp_server
    print(f"[OK] ftp_server.py loaded")
    print(f"     TLS cert: {ftp_server.config.TLS_CERT_FILE}")
    print(f"     TLS key: {ftp_server.config.TLS_KEY_FILE}")
except Exception as e:
    print(f"[FAIL] ftp_server.py: {e}")

# 5. Verify certificates exist
try:
    from pathlib import Path
    cert = Path("certs/cert.pem")
    key = Path("certs/key.pem")
    assert cert.exists(), "cert.pem missing"
    assert key.exists(), "key.pem missing"
    cert_size = cert.stat().st_size
    key_size = key.stat().st_size
    print(f"[OK] TLS certificates present:")
    print(f"     cert.pem ({cert_size} bytes)")
    print(f"     key.pem ({key_size} bytes)")
except Exception as e:
    print(f"[FAIL] Certificates: {e}")

print("=" * 60)
print("VERIFICATION COMPLETE")
print("=" * 60)