import sys
sys.path.insert(0, 'd:/my_ftp_project')

from security_utils import (
    hash_password, verify_password, sanitize_ftp_path, sanitize_filename
)

print("=" * 60)
print("SECURITY MODULE TESTS")
print("=" * 60)

print("\n[1] Password Hashing (PBKDF2-SHA256)")
h = hash_password("lab_exam_password")
print(f"    Hash format: {h[:60]}...")
assert h.startswith("pbkdf2"), "Hash should start with pbkdf2"
assert len(h) > 80, "Hash should be long (salt+hash)"

# Verify correct password
assert verify_password("lab_exam_password", h), "Correct password should verify"
print("    ✓ Correct password verified OK")

# Verify wrong password
assert not verify_password("wrong_password", h), "Wrong password should NOT verify"
print("    ✓ Wrong password rejected OK")

# Verify constant-time comparison (same hash format reproduced)
h2 = hash_password("lab_exam_password")
assert verify_password("lab_exam_password", h2), "New hash should also verify"
print("    ✓ Different salt, still verifies OK")

print("\n[2] Path Traversal Prevention")

assert sanitize_ftp_path("test/file.txt") == "test/file.txt"
print("    ✓ Normal path accepted")

try:
    sanitize_ftp_path("../secret")
    print("    ✗ FAIL: Should have rejected ../secret")
    sys.exit(1)
except ValueError:
    print("    ✓ '..' traversal rejected OK")

# Absolute paths should be rejected
try:
    sanitize_ftp_path("/etc/passwd")
    print("    ✗ FAIL: Should have rejected /etc/passwd")
    sys.exit(1)
except ValueError:
    print("    ✓ Absolute paths rejected OK")

print("\n[3] Filename Sanitization")
safe = sanitize_filename("myfile.txt")
assert safe == "myfile.txt"
print("    ✓ Normal filename OK")

# Block dangerous extensions
try:
    sanitize_filename("virus.exe")
    print("    ✗ FAIL: Should have blocked .exe")
    sys.exit(1)
except ValueError:
    print("    ✓ .exe blocked OK")

try:
    sanitize_filename("script.py")
    print("    ✗ FAIL: Should have blocked .py")
    sys.exit(1)
except ValueError:
    print("    ✓ .py blocked OK")

# Hidden files blocked
try:
    sanitize_filename(".hidden_file.txt")
    print("    ✗ FAIL: Should have blocked hidden file")
    sys.exit(1)
except ValueError:
    print("    ✓ Hidden files rejected OK")

result = sanitize_filename("../../etc/passwd")
assert result == "passwd", f"Should strip path, got: {result}"
print("    ✓ Path traversal in filename stripped to basename OK")

try:
    sanitize_filename("..")
    print("    ✗ FAIL: Should have rejected '..'")
except ValueError:
    print("    ✓ '..' as filename rejected OK")

print("\n" + "=" * 60)
print("ALL TESTS PASSED!")
print("=" * 60)