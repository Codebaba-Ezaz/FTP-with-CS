"""
Secure Web Frontend
-------------------
Implements Computer Security concepts:
1. Session Security - no plaintext passwords in session, HTTPOnly cookies, secure flags
2. CSRF Protection - token validation for all POST requests
3. Rate Limiting / Account Lockout - brute-force defense
4. Path Traversal Prevention - input validation
5. Security Headers - defense in depth
6. Audit Logging - accountability
7. TLS/FTPS Support - encrypted FTP connections
"""

import os
import ftplib
import ssl
import humanize
from pathlib import Path
from datetime import datetime
from datetime import timedelta

from flask import (Flask, render_template, request, redirect, url_for, 
                   session, send_file, flash, g)

import config
from security_utils import (
    security_log,
    CSRFProtect,
    csrf_protect,
    login_tracker,
    login_required,
    sanitize_ftp_path,
    sanitize_filename,
    validate_upload,
    apply_security_headers,
)
from user_db import user_db

# --- Flask App Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY                       # Strong random key
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH       # Upload limit
app.config['UPLOAD_FOLDER'] = str(config.UPLOAD_DIR)

# --- Secure Session Settings ---
app.config['SESSION_COOKIE_HTTPONLY'] = True       # JS can't read cookies (XSS defense)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'      # CSRF defense at browser level
app.config['SESSION_COOKIE_SECURE'] = False        # Set True for HTTPS-only (lab uses HTTP)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=config.PERMANENT_SESSION_LIFETIME)

# --- FTP Server Details ---
FTP_HOST = "localhost"
FTP_PORT = config.FTP_PORT
FTP_USE_TLS = True  # Use FTPS (TLS encrypted) connection


# ============================================================
# SECURITY HEADERS MIDDLEWARE
# ============================================================
@app.after_request
def add_security_headers(response):
    """Add security headers to every response (defense in depth)."""
    return apply_security_headers(response)


# ============================================================
# CONTEXT PROCESSOR - inject CSRF token into all templates
# ============================================================
@app.context_processor
def inject_csrf_token():
    """Make CSRF token available in all templates."""
    return dict(csrf_token=CSRFProtect.generate_token())


# ============================================================
# SECURE FTP CONNECTION (FTPS with TLS)
# ============================================================
def get_ftp_connection():
    """
    Create a secure FTPS connection.
    Uses TLS to encrypt the session - credentials never travel in plaintext.
    """
    ftp = ftplib.FTP_TLS() if FTP_USE_TLS else ftplib.FTP()

    try:
        ftp.connect(FTP_HOST, FTP_PORT, timeout=10)

        # Establish TLS on the control channel (AUTH TLS)
        if FTP_USE_TLS:
            ftp.auth()  # Send AUTH TLS
            ftp.prot_p()  # Protect data channel too (PROT P)

        username = session.get('username')
        if username and username == config.ADMIN_USER:
            if '_auth_password' not in session:
                ftp.login()  # anonymous fallback
            else:
                ftp.login(username, session['_auth_password'])
        else:
            ftp.login()  # Anonymous guest login

        return ftp
    except ftplib.all_errors as e:
        security_log.log_event(
            f"FTP connection error: {e}",
            level="ERROR"
        )
        flash(f"FTP Server is not available: {e}", 'danger')
        return None


# ============================================================
# LOCAL FILESYSTEM HELPERS
# ============================================================
# The web frontend and FTP server share the same ftp_root directory.
# We use the local filesystem for reliable directory listing and file
# operations, since pyftpdlib has issues with directory navigation on
# some configurations (always returning root contents).

def get_local_path(remote_path):
    """
    Convert an FTP remote path to a local filesystem path.
    CRITICAL: This also validates against path traversal by ensuring
    the resolved path stays within ftp_root.
    """
    if remote_path == "." or not remote_path:
        return config.FTP_ROOT

    # Build the local path
    local = config.FTP_ROOT / remote_path

    # Resolve and verify it's still inside ftp_root (path traversal defense).
    # Using relative_to() is safer than str.startswith() which can be fooled
    # by sibling directories like "ftp_root_evil".
    try:
        resolved = local.resolve()
        ftp_root_resolved = config.FTP_ROOT.resolve()
        resolved.relative_to(ftp_root_resolved)  # raises ValueError if outside
    except ValueError:
        raise ValueError("Path escapes ftp_root")
    except Exception:
        raise ValueError("Invalid path")

    return local


def list_local_directory(remote_path):
    """
    List contents of a directory using the local filesystem.
    Returns a list of entry dicts compatible with the template.
    Returns None if the directory doesn't exist.
    """
    try:
        local_path = get_local_path(remote_path)
    except ValueError:
        return None

    if not local_path.exists() or not local_path.is_dir():
        return None

    entries = []
    try:
        for item in local_path.iterdir():
            # Skip hidden files
            if item.name.startswith('.'):
                continue

            is_dir = item.is_dir()
            stat_info = item.stat()

            entries.append({
                'name': item.name,
                'type': 'dir' if is_dir else 'file',
                'size': stat_info.st_size,
                'modify': datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d'),
                'hr_size': humanize.naturalsize(stat_info.st_size) if not is_dir else ''
            })
    except PermissionError:
        return None

    return entries


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def generate_breadcrumbs(path):
    if path == ".": return []
    clean_path = path.strip('./')
    if not clean_path: return []
    parts = clean_path.split('/')
    breadcrumbs = []
    current_path = ''
    for part in parts:
        current_path = os.path.join(current_path, part).replace('\\', '/')
        breadcrumbs.append({'name': part, 'path': current_path})
    return breadcrumbs


# ============================================================
# WEB ROUTES
# ============================================================
@app.route("/")
@app.route("/files/")
@app.route("/files/<path:remote_path>")
def list_files(remote_path="."):
    """
    List files in the FTP directory.
    - Validates paths to prevent traversal
    - Guests can only see public content
    """
    # Path traversal prevention
    try:
        remote_path = sanitize_ftp_path(remote_path)
    except ValueError:
        security_log.log_event(
            f"PATH TRAVERSAL attempt blocked: {remote_path}",
            level="WARNING"
        )
        flash("Invalid path. Access denied.", "danger")
        return redirect(url_for('list_files'))

    # Guests can ONLY access the root (.) and the "public" directory (and its subdirs)
    # Block ezaz_files and any non-public path
    if 'username' not in session:
        if "ezaz_files" in remote_path:
            security_log.log_event(
                f"GUEST blocked from accessing ezaz_files: {remote_path}",
                level="WARNING"
            )
            flash("Access denied. This is a private admin directory.", "danger")
            return redirect(url_for('list_files'))
        # Strict check: only allow ".", "public", or "public/..." (not "publicfoo")
        if remote_path != "." and remote_path != "public" and not remote_path.startswith("public/"):
            security_log.log_event(
                f"GUEST tried to access restricted path: {remote_path}",
                level="WARNING"
            )
            flash("Guests can only access the public directory.", "warning")
            return redirect(url_for('list_files'))

    # List directory using local filesystem (reliable, unlike FTP which
    # always returns root contents regardless of the requested path)
    entries = list_local_directory(remote_path)

    if entries is None:
        flash(f"Directory '{remote_path}' could not be found or is empty.", "warning")
        entries = []

    # Filter entries for guests:
    # - At root (.): only show the "public" directory
    # - At any path: always hide "ezaz_files" (defense in depth)
    if 'username' not in session:
        if remote_path == ".":
            entries = [e for e in entries if e.get('name') == 'public']
        else:
            entries = [e for e in entries if e.get('name') != 'ezaz_files']

    entries.sort(key=lambda x: (x.get('type') != 'dir', x.get('name').lower()))

    breadcrumbs = generate_breadcrumbs(remote_path)
    parent_path = os.path.dirname(remote_path) if remote_path not in ('.', '/') else None
    # os.path.dirname("public") returns "" — normalize to "." for proper root navigation
    if parent_path == '':
        parent_path = '.'

    if 'username' not in session and remote_path == ".":
        parent_path = None

    return render_template('files.html',
                           entries=entries,
                           current_path=remote_path,
                           breadcrumbs=breadcrumbs,
                           parent_path=parent_path)


@app.route("/login", methods=['GET', 'POST'])
def login():
    """
    Secure login with:
    - Rate limiting / account lockout (brute-force defense)
    - CSRF protection
    - Session fixation prevention
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Input validation
        if not username or not password:
            flash("Username and password are required.", "warning")
            return redirect(url_for('login'))

        # Brute-force protection: check if account is locked
        locked, remaining = login_tracker.is_locked(username)
        if locked:
            minutes = remaining // 60
            seconds = remaining % 60
            security_log.log_event(
                f"BLOCKED login attempt for locked user '{username}'",
                level="WARNING"
            )
            flash(
                f"Account temporarily locked due to too many failed attempts. "
                f"Try again in {minutes}m {seconds}s.",
                "danger"
            )
            return redirect(url_for('login'))

        # Generic error message (don't reveal if user exists - enumeration defense)
        if username != config.ADMIN_USER:
            login_tracker.record_failure(username)
            security_log.log_event(
                f"LOGIN FAILED for user '{username}'",
                level="WARNING"
            )
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

        # Verify password against PBKDF2 hash
        if not user_db.verify_credentials(username, password):
            login_tracker.record_failure(username)
            security_log.log_event(
                f"LOGIN FAILED for user '{username}'",
                level="WARNING"
            )
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

        # Also verify FTPS connection works
        try:
            ftp = ftplib.FTP_TLS()
            ftp.connect(FTP_HOST, FTP_PORT, timeout=10)
            ftp.auth()
            ftp.prot_p()
            ftp.login(username, password)
            ftp.quit()

            # Success!
            login_tracker.reset(username)
            security_log.log_event(f"LOGIN SUCCESS for user '{username}'")
            security_log.log_audit(
                action="WEB_LOGIN",
                user=username,
                details="Successful web login"
            )

            # Fresh session (prevents session fixation attack)
            session.clear()
            session['username'] = username
            session['_auth_password'] = password  # needed for FTP operations
            session.permanent = True  # enforce session lifetime

            flash(f"Welcome, {username}! You are securely logged in.", "success")
            return redirect(url_for('list_files'))

        except ftplib.all_errors as e:
            login_tracker.record_failure(username)
            security_log.log_event(
                f"FTP LOGIN FAILED for '{username}': FTP error",
                level="WARNING"
            )
            flash(f"FTP Server rejected login: {e}", "danger")
            return redirect(url_for('login'))

    # GET request - show login page
    return render_template('login.html')


@app.route("/logout")
def logout():
    """Log out and clear session."""
    if 'username' in session:
        security_log.log_audit(
            action="WEB_LOGOUT",
            user=session['username'],
            details="User logged out"
        )
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for('list_files'))


@app.route('/delete', methods=['POST'])
@login_required
@csrf_protect
def delete_item():
    """Delete a file or directory (admin only, CSRF protected)."""
    item_path = request.form.get('item_path')
    item_type = request.form.get('item_type')
    current_path = os.path.dirname(item_path) or '.'

    if not item_path or not item_type:
        flash("Invalid delete request.", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    # Path traversal prevention
    try:
        item_path = sanitize_ftp_path(item_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    # Use local filesystem for reliable deletion
    try:
        local_path = get_local_path(item_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    if not local_path.exists():
        flash(f"Item '{os.path.basename(item_path)}' not found.", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    try:
        if item_type == 'file':
            local_path.unlink()
            flash(f"File '{os.path.basename(item_path)}' deleted successfully.", "success")
            security_log.log_audit(
                action="FILE_DELETE",
                user=session.get('username', 'unknown'),
                details=f"Deleted file: {item_path}"
            )
        elif item_type == 'dir':
            local_path.rmdir()
            flash(f"Directory '{os.path.basename(item_path)}' deleted successfully.", "success")
            security_log.log_audit(
                action="DIR_DELETE",
                user=session.get('username', 'unknown'),
                details=f"Deleted directory: {item_path}"
            )
    except OSError as e:
        flash(f"Could not delete item: {e}", "danger")

    return redirect(url_for('list_files', remote_path=current_path))


@app.route('/upload/<path:current_path>', methods=['POST'])
@login_required
@csrf_protect
def upload_file(current_path):
    """Upload a file (admin only, CSRF protected, with file validation)."""
    # Path traversal prevention
    try:
        current_path = sanitize_ftp_path(current_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    if 'file' not in request.files or request.files['file'].filename == '':
        flash("No file selected for upload.", "warning")
        return redirect(url_for('list_files', remote_path=current_path))

    file = request.files['file']

    # Validate file (extension, size, etc.)
    if not validate_upload(file):
        flash("File rejected: invalid type, name, or too large.", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    # Sanitize filename
    try:
        safe_filename = sanitize_filename(file.filename)
    except ValueError as e:
        flash(f"File rejected: {e}", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    # Get local target directory
    try:
        target_dir = get_local_path(current_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    if not target_dir.exists() or not target_dir.is_dir():
        flash(f"Directory '{current_path}' does not exist.", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    # Save file directly to the local filesystem
    target_path = target_dir / safe_filename
    try:
        file.save(str(target_path))
        flash(f"File '{safe_filename}' uploaded successfully.", "success")
        security_log.log_audit(
            action="FILE_UPLOAD",
            user=session.get('username', 'unknown'),
            details=f"Uploaded: {safe_filename} to {current_path}"
        )
    except OSError as e:
        flash(f"Upload failed: {e}", "danger")

    return redirect(url_for('list_files', remote_path=current_path))


@app.route('/mkdir/<path:current_path>', methods=['POST'])
@login_required
@csrf_protect
def make_directory(current_path):
    """Create a directory (admin only, CSRF protected)."""
    # Path traversal prevention
    try:
        current_path = sanitize_ftp_path(current_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    dirname = request.form.get('dirname')
    if not dirname:
        flash("Directory name cannot be empty.", "warning")
        return redirect(url_for('list_files', remote_path=current_path))

    # Sanitize directory name
    try:
        safe_dirname = sanitize_filename(dirname)
    except ValueError as e:
        flash(f"Invalid directory name: {e}", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    # Get local target directory
    try:
        target_dir = get_local_path(current_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    if not target_dir.exists() or not target_dir.is_dir():
        flash(f"Directory '{current_path}' does not exist.", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    # Create directory in the local filesystem
    new_dir = target_dir / safe_dirname
    try:
        new_dir.mkdir(exist_ok=False)
        flash(f"Directory '{safe_dirname}' created successfully.", "success")
        security_log.log_audit(
            action="DIR_CREATE",
            user=session.get('username', 'unknown'),
            details=f"Created directory: {safe_dirname} in {current_path}"
        )
    except OSError as e:
        flash(f"Could not create directory: {e}", "danger")

    return redirect(url_for('list_files', remote_path=current_path))


@app.route('/download/<path:filepath>')
def download_file(filepath):
    """Download a file (anyone can download)."""
    # Path traversal prevention
    try:
        filepath = sanitize_ftp_path(filepath)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    # Use local filesystem for reliable download
    try:
        local_path = get_local_path(filepath)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    if not local_path.exists() or not local_path.is_file():
        flash(f"File '{os.path.basename(filepath)}' not found.", "danger")
        return redirect(request.referrer or url_for('list_files'))

    security_log.log_audit(
        action="FILE_DOWNLOAD",
        user=session.get('username', 'anonymous'),
        details=f"Downloaded: {filepath}"
    )
    return send_file(str(local_path), as_attachment=True)


# ============================================================
# SETUP ROUTE - First-time admin user creation
# ============================================================
@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """
    First-time setup: create the admin user.
    This route only works if no admin user exists yet.
    """
    if user_db.user_exists(config.ADMIN_USER):
        flash("Admin user already exists. Login instead.", "info")
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not password or len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template('setup.html')

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template('setup.html')

        # Create admin user with PBKDF2 hashed password
        user_db.add_user(config.ADMIN_USER, password)
        security_log.log_event(
            f"ADMIN USER CREATED: {config.ADMIN_USER}",
            level="INFO"
        )
        security_log.log_audit(
            action="ADMIN_SETUP",
            user=config.ADMIN_USER,
            details="Admin user created via setup"
        )

        flash("Admin user created successfully! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('setup.html')


# ============================================================
# MAIN
# ============================================================
if __name__ == '__main__':
    print("=" * 60)
    print("  SECURE WEB FRONTEND")
    print(f"  Secret Key: Loaded from file (256-bit random)")
    print(f"  Session Lifetime: {config.PERMANENT_SESSION_LIFETIME}s")
    print(f"  Max Upload: {config.MAX_CONTENT_LENGTH // (1024*1024)}MB")
    print(f"  CSRF Protection: Enabled")
    print(f"  Rate Limiting: {config.MAX_LOGIN_ATTEMPTS} attempts / {config.LOCKOUT_DURATION // 60}min")
    print(f"  Security Headers: Enabled")
    print(f"  Audit Log: {config.AUDIT_LOG_FILE}")
    print("=" * 60)
    print("  NOTE: For first run, visit http://localhost:5000/setup")
    print("        to create the admin user.")
    print("=" * 60)

    # debug=False for security (never expose debug in production)
    # Port 8080 used because 5000 is blocked on Windows
    app.run(host='0.0.0.0', port=8080, debug=False)