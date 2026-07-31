# ðŸ” Secure FTP Project - Computer Security Lab Demo Guide

## ðŸ“‹ Security Features Implemented

This project demonstrates **10 core Computer Security concepts**:

### 1. **Password Hashing (PBKDF2)**
- File: `security_utils.py` â†’ `hash_password()` / `verify_password()`
- Algorithm: PBKDF2-HMAC-SHA256
- Passwords are NEVER stored as plaintext
- Uses salt (random 16 bytes) to prevent rainbow table attacks
- Uses constant-time comparison (`hmac.compare_digest`) to prevent timing attacks

### 2. **CSRF Protection**
- File: `security_utils.py` â†’ `CSRFProtect` class
- Every POST form includes a hidden CSRF token
- Token validated server-side before processing
- Prevents Cross-Site Request Forgery attacks

### 3. **Brute-Force Defense (Rate Limiting)**
- File: `security_utils.py` â†’ `LoginAttemptTracker`
- Account locks after 5 failed attempts
- Lockout duration: 15 minutes
- Prevents password guessing attacks

### 4. **TLS/FTPS Encryption**
- File: `ftp_server.py` â†’ `SecureFTPHandler`
- FTP over TLS (FTPS) - RFC 4217
- Self-signed X.509 certificate (RSA-2048)
- Credentials + data encrypted in transit

### 5. **Path Traversal Prevention**
- File: `security_utils.py` â†’ `sanitize_ftp_path()` / `sanitize_filename()`
- Blocks `..` directory traversal
- Blocks absolute paths
- Blocks dangerous file extensions (.exe, .py, .php, etc.)

### 6. **Security Headers**
- File: `config.py` â†’ `SECURITY_HEADERS`
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY (clickjacking defense)
- Content-Security-Policy
- Cache-Control: no-store

### 7. **Session Security**
- HTTPOnly cookies (XSS defense)
- SameSite=Lax (CSRF defense)
- Session timeout (15 minutes)
- Session fixation prevention (fresh session on login)

### 8. **Audit Logging**
- File: `security_utils.py` â†’ `SecurityLogger`
- Logs: `logs/security.log` + `logs/audit.log`
- Tracks: logins, uploads, downloads, deletions
- Provides accountability & non-repudiation

### 9. **Input Validation**
- File upload size limit (10 MB)
- Dangerous extension blocking
- Filename sanitization
- Path validation

### 10. **Access Control**
- Admin-only operations (delete, upload, mkdir)
- Guest users = read-only
- `@login_required` decorator

---

## ðŸš€ How to Run the Demo

### Step 1: Create Admin User (already done)
```bash
python quick_admin.py
```
Output: `users.json CREATED` (instant)

### Step 2: Start the FTPS Server
```bash
python ftp_server.py
```
- Runs on port 2121
- TLS encrypted

### Step 3: Start the Web Frontend
```bash
python web_frontend.py
```
- Runs on port 5000

### Step 4: Open Browser
```
http://localhost:5000
```

### Login Credentials:
- **Username:** `ezaz`
- **Password:** `SecurePass@2026`

---

## ðŸ“ Project Files

| File | Purpose |
|------|---------|
| `config.py` | Security configuration (iterations, headers, limits) |
| `security_utils.py` | PBKDF2, CSRF, rate limiting, logging, validation |
| `user_db.py` | User database with hashed passwords |
| `ftp_server.py` | FTPS server with TLS encryption |
| `web_frontend.py` | Secure Flask web app |
| `generate_cert.py` | TLS certificate generator |
| `quick_admin.py` | Instant admin user creation |
| `templates/login.html` | Login page with CSRF token |
| `templates/files.html` | File browser with CSRF tokens |
| `templates/setup.html` | First-time admin setup |
| `certs/cert.pem` | TLS certificate |
| `certs/key.pem` | TLS private key |
| `logs/security.log` | Security event log |
| `logs/audit.log` | Audit trail |
| `users.json` | User database (hashed passwords) |

---

## ðŸŽ¯ Key Demo Points for Professor

1. **Show `users.json`** - password is hashed, not plaintext
2. **Show `security_utils.py`** - PBKDF2 implementation
3. **Try wrong password 5 times** - account locks (brute-force defense)
4. **Show `logs/audit.log`** - all actions are logged
5. **Show CSRF tokens** in HTML source of forms
6. **Show TLS certificate** in `certs/` folder
7. **Try uploading `.exe` file** - blocked by security
