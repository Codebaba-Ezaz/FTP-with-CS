# ðŸŽ¯ ATTACK DEMONSTRATION GUIDE
## How to Show Your Professor: "Attacker tries X â†’ System blocks it"

This guide shows you how to DEMONSTRATE live attacks and how your system
prevents them. This will impress your professor!

---

## ATTACK 1: Malicious File Upload (Most Impressive!)

### The Attack:
An attacker tries to upload a malicious executable or script file
to hack your server.

### How to Demo:
1. Start both servers:
   ```
   python ftp_server.py
   python web_frontend.py
   ```
2. Open http://localhost:5000 and login as admin
3. Try to upload these files:
   - Create a file called `virus.exe` (just a text file renamed)
   - Create a file called `hack.py` (just a text file renamed)
   - Create a file called `shell.php` (just a text file renamed)

### What Happens:
```
âŒ File rejected: File extension '.exe' is blocked for security reasons.
âŒ File rejected: File extension '.py' is blocked for security reasons.
âŒ File rejected: File extension '.php' is blocked for security reasons.
```

### What to Say:
> "Sir, an attacker might try to upload a malicious executable or PHP shell
> to take control of the server. My system blocks dangerous file extensions
> like .exe, .py, .php, .bat, .sh, and more. This is **input validation** -
> a core Computer Security concept."

**Show code:** `security_utils.py` â†’ `sanitize_filename()` + `config.py` â†’ `BLOCKED_EXTENSIONS`

---

## ATTACK 2: Path Traversal Attack

### The Attack:
An attacker tries to access files OUTSIDE the FTP directory using `../`
For example: `../../etc/passwd` or `../../Windows/System32/config/SAM`

### How to Demo:
1. Open your browser and try this URL:
   ```
   http://localhost:5000/files/../../etc/passwd
   ```
2. Or try:
   ```
   http://localhost:5000/files/../../../Windows/System32
   ```

### What Happens:
```
âŒ Invalid path. Access denied.
```

### What to Say:
> "Sir, a path traversal attack is when an attacker uses `../` to navigate
> outside the allowed directory and access system files like `/etc/passwd`
> on Linux or `Windows\System32` on Windows.
>
> My system blocks this in `sanitize_ftp_path()` - it rejects any path
> containing `..` or starting with `/`. This prevents the attacker from
> accessing files outside the FTP root directory."

**Show code:** `security_utils.py` â†’ `sanitize_ftp_path()`

---

## ATTACK 3: Brute-Force Password Attack

### The Attack:
An attacker tries to guess the admin password by trying many passwords.

### How to Demo:
1. Open http://localhost:5000/login
2. Enter username: `ezaz`
3. Enter WRONG password 5 times (e.g., "wrong1", "wrong2", etc.)

### What Happens:
```
Attempt 1: âŒ Invalid credentials.
Attempt 2: âŒ Invalid credentials.
Attempt 3: âŒ Invalid credentials.
Attempt 4: âŒ Invalid credentials.
Attempt 5: âŒ Invalid credentials.
â†’ Account temporarily locked due to too many failed attempts.
  Try again in 15m 0s.
```

### What to Say:
> "Sir, a brute-force attack is when an attacker tries thousands of passwords
> to guess the correct one. My system tracks failed login attempts and
> **locks the account after 5 failures** for 15 minutes.
>
> This means an attacker can only try 5 passwords every 15 minutes.
> To try 1 million passwords would take over 3 years!
>
> All failed attempts are also logged in `logs/security.log` for accountability."

**Show code:** `security_utils.py` â†’ `LoginAttemptTracker` class
**Show logs:** Open `logs/security.log` â†’ show the failed attempts

---

## ATTACK 4: CSRF (Cross-Site Request Forgery)

### The Attack:
An attacker creates a fake website that tricks the logged-in admin into
deleting a file without their knowledge.

### How to Demo:
1. Login as admin at http://localhost:5000
2. Open browser Developer Tools (F12) â†’ Console
3. Try to submit a form WITHOUT the CSRF token:
   ```javascript
   fetch('/delete', {
       method: 'POST',
       body: 'item_path=welcome.txt&item_type=file'
   })
   ```

### What Happens:
```
âŒ Security token invalid. Please try again.
```

### What to Say:
> "Sir, CSRF is when an attacker tricks a logged-in user into submitting
> a form without their knowledge. For example, deleting files.
>
> My system generates a random **CSRF token** for each session. Every form
> includes this token as a hidden field. When the form is submitted, the
> server checks if the token matches. If an attacker submits a form from
> another website, they don't have the token, so the request is REJECTED."

**Show code:** `security_utils.py` â†’ `CSRFProtect` class
**Show HTML:** `templates/files.html` â†’ `<input type="hidden" name="csrf_token">`

---

## ATTACK 5: Unauthorized Access (No Login)

### The Attack:
An attacker tries to delete/upload/create files WITHOUT logging in.

### How to Demo:
1. Open http://localhost:5000 (don't login - stay as Guest)
2. Try to access: http://localhost:5000/delete (POST request)
3. Try to access: http://localhost:5000/upload (POST request)

### What Happens:
```
âŒ Please login as admin to access this feature.
```

### What to Say:
> "Sir, this is **access control**. Only authenticated admin users can
> delete files, upload files, or create directories. Guest users can
> only view and download files.
>
> I used a `@login_required` decorator that checks the session before
> allowing access. If an unauthenticated user tries to access these
> endpoints, they're redirected to login."

**Show code:** `security_utils.py` â†’ `login_required` decorator

---

## ATTACK 6: Plaintext Password Theft (Before vs After)

### The Attack:
An attacker gains access to the server files and tries to read passwords.

### How to Demo (Before vs After):

**BEFORE (old code):**
```python
# Old ftp_server.py - password in plaintext!
authorizer.add_user("ezaz", "password123", ftp_root_dir, perm="elradfmwMT")
```
> "Sir, before implementing security, the password was stored directly
> in the source code as 'password123'. Anyone who reads the code knows
> the password."

**AFTER (new code):**
```json
// users.json - password is HASHED!
{
  "ezaz": {
    "password_hash": "pbkdf2:sha256:1000$04935122...$256e6dfd...",
    "permissions": "elradfmwMT"
  }
}
```
> "Now, the password is hashed using PBKDF2 with salt. Even if an attacker
> steals the `users.json` file, they cannot reverse the hash to get the
> original password. They would need to brute-force it, which takes years."

**Show:** Open `users.json` â†’ show the hashed password

---

## ATTACK 7: Network Sniffing (FTP vs FTPS)

### The Attack:
An attacker on the same WiFi network uses a packet sniffer (like Wireshark)
to capture FTP traffic and steal passwords.

### How to Demo (Explain):

**BEFORE (Standard FTP):**
> "Sir, standard FTP sends everything in plaintext. If an attacker is on
> the same network, they can use Wireshark to capture the username and
> password as they travel across the network."

**AFTER (FTPS - FTP over TLS):**
> "Now, I implemented FTPS - FTP over TLS. I generated an RSA-2048
> certificate and configured the FTP server to require TLS encryption.
> Both the login credentials AND file transfers are now encrypted.
> An attacker capturing network traffic would only see encrypted data."

**Show:**
- Open `certs/cert.pem` â†’ show the TLS certificate
- Open `ftp_server.py` â†’ show `SecureFTPHandler` class
- Open `generate_cert.py` â†’ show how the certificate was generated

---

## ðŸŽ¯ QUICK DEMO CHECKLIST (3 minutes)

For a quick 3-minute demo, show these 3 attacks:

### 1. Malicious Upload (1 min)
- Try uploading `virus.exe` â†’ BLOCKED âœ…
- Say: "Input validation blocks dangerous files"

### 2. Brute-Force (1 min)
- Try wrong password 5 times â†’ LOCKED âœ…
- Say: "Rate limiting prevents brute-force attacks"

### 3. Hashed Password (30 sec)
- Show `users.json` â†’ password is hashed âœ…
- Say: "PBKDF2 hashing - password never stored as plaintext"

---

## ðŸ’¡ BONUS: What to Say if Professor Asks Questions

**Q: "Why PBKDF2 and not just SHA-256?"**
> "SHA-256 is too fast - an attacker can try millions of hashes per second.
> PBKDF2 adds iterations to slow down each hash, making brute-force
> impractical. It also uses a salt to prevent rainbow table attacks."

**Q: "Why is the salt important?"**
> "Without a salt, two users with the same password would have the same hash.
> An attacker could use a precomputed 'rainbow table' to crack them.
> The salt makes each hash unique, even for the same password."

**Q: "What is constant-time comparison?"**
> "Normal string comparison stops at the first different character.
> An attacker can measure the time to determine how many characters match.
> `hmac.compare_digest()` always takes the same time, preventing timing attacks."

**Q: "Why self-signed certificate?"**
> "For this lab, I generated a self-signed certificate. In production,
> you'd use a certificate from a trusted Certificate Authority (CA)
> like Let's Encrypt. The encryption is the same, but the CA verifies
> identity."

**Q: "What is defense in depth?"**
> "It means using multiple layers of security. If one layer fails,
> others still protect the system. For example: password hashing +
> brute-force defense + TLS encryption + CSRF protection - all work
> together."
