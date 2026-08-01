import os
import ftplib
import ssl
import socket
import threading
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

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.config['UPLOAD_FOLDER'] = str(config.UPLOAD_DIR)

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=config.PERMANENT_SESSION_LIFETIME)

FTP_HOST = "localhost"
FTP_PORT = config.FTP_TLS_PORT if config.FTP_REQUIRE_TLS else config.FTP_PORT
FTP_USE_TLS = config.FTP_REQUIRE_TLS


def start_ftp_listener_if_needed():
    try:
        with socket.create_connection((FTP_HOST, FTP_PORT), timeout=1):
            return
    except OSError:
        pass

    def run_server():
        import ftp_server
        ftp_server.main()

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    for _ in range(10):
        try:
            with socket.create_connection((FTP_HOST, FTP_PORT), timeout=1):
                return
        except OSError:
            import time
            time.sleep(0.5)


@app.after_request
def add_security_headers(response):
    return apply_security_headers(response)


@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=CSRFProtect.generate_token())


@app.context_processor
def inject_admin_user():
    return dict(admin_username=config.ADMIN_USER)


def get_ftp_connection():
    ftp = ftplib.FTP_TLS() if config.FTP_REQUIRE_TLS else ftplib.FTP()

    try:
        ftp.connect(FTP_HOST, FTP_PORT, timeout=5)

        if config.FTP_REQUIRE_TLS:
            ftp.auth()
            ftp.prot_p()

        username = session.get('username')
        if username and '_auth_password' in session:
            ftp.login(username, session['_auth_password'])
        else:
            ftp.login()

        return ftp
    except ftplib.all_errors as e:
        security_log.log_event(f"FTP connection error: {e}", level="ERROR")
        flash(f"FTP Server is not available: {e}", 'danger')
        return None


def get_local_path(remote_path):
    if remote_path == "." or not remote_path:
        return config.FTP_ROOT

    local = config.FTP_ROOT / remote_path

    try:
        resolved = local.resolve()
        ftp_root_resolved = config.FTP_ROOT.resolve()
        resolved.relative_to(ftp_root_resolved)
    except ValueError:
        raise ValueError("Path escapes ftp_root")
    except Exception:
        raise ValueError("Invalid path")

    return local


def list_local_directory(remote_path):
    try:
        local_path = get_local_path(remote_path)
    except ValueError:
        return None

    if not local_path.exists() or not local_path.is_dir():
        return None

    entries = []
    try:
        for item in local_path.iterdir():
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


@app.route("/")
@app.route("/files/")
@app.route("/files/<path:remote_path>")
def list_files(remote_path="."):
    try:
        remote_path = sanitize_ftp_path(remote_path)
    except ValueError:
        security_log.log_event(f"PATH TRAVERSAL attempt blocked: {remote_path}", level="WARNING")
        flash("Invalid path. Access denied.", "danger")
        return redirect(url_for('list_files'))

    is_admin = session.get('username') == config.ADMIN_USER

    if not is_admin and "ezaz_files" in remote_path:
        security_log.log_event(
            f"Non-admin blocked from accessing ezaz_files: {remote_path} "
            f"(user='{session.get('username', 'guest')}')",
            level="WARNING"
        )
        flash("Access denied. This is a private admin directory.", "danger")
        return redirect(url_for('list_files'))

    if 'username' not in session:
        if remote_path != "." and remote_path != "public" and not remote_path.startswith("public/"):
            security_log.log_event(f"GUEST tried to access restricted path: {remote_path}", level="WARNING")
            flash("Guests can only access the public directory.", "warning")
            return redirect(url_for('list_files'))

    entries = list_local_directory(remote_path)

    if entries is None:
        flash(f"Directory '{remote_path}' could not be found or is empty.", "warning")
        entries = []

    if 'username' not in session:
        if remote_path == ".":
            entries = [e for e in entries if e.get('name') == 'public']
        else:
            entries = [e for e in entries if e.get('name') != 'ezaz_files']
    elif not is_admin:
        entries = [e for e in entries if e.get('name') != 'ezaz_files']

    entries.sort(key=lambda x: (x.get('type') != 'dir', x.get('name').lower()))

    breadcrumbs = generate_breadcrumbs(remote_path)
    parent_path = os.path.dirname(remote_path) if remote_path not in ('.', '/') else None
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
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Username and password are required.", "warning")
            return redirect(url_for('login'))

        locked, remaining = login_tracker.is_locked(username)
        if locked:
            minutes = remaining // 60
            seconds = remaining % 60
            security_log.log_event(f"BLOCKED login attempt for locked user '{username}'", level="WARNING")
            flash(f"Account temporarily locked. Try again in {minutes}m {seconds}s.", "danger")
            return redirect(url_for('login'))

        user_db.reload()

        if not user_db.user_exists(username):
            login_tracker.record_failure(username)
            security_log.log_event(f"LOGIN FAILED for unknown user '{username}'", level="WARNING")
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

        if not user_db.verify_credentials(username, password):
            login_tracker.record_failure(username)
            security_log.log_event(f"LOGIN FAILED for user '{username}'", level="WARNING")
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login'))

        try:
            if config.FTP_REQUIRE_TLS:
                ftp = ftplib.FTP_TLS()
                ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
                ftp.auth()
                ftp.prot_p()
            else:
                ftp = ftplib.FTP()
                ftp.connect(FTP_HOST, FTP_PORT, timeout=5)
            ftp.login(username, password)
            ftp.quit()

            login_tracker.reset(username)
            security_log.log_event(f"LOGIN SUCCESS for user '{username}'")
            security_log.log_audit(action="WEB_LOGIN", user=username, details="Successful web login")

            session.clear()
            session['username'] = username
            session['_auth_password'] = password
            session.permanent = True

            flash(f"Welcome, {username}! You are securely logged in.", "success")
            return redirect(url_for('list_files'))

        except ftplib.all_errors as e:
            login_tracker.record_failure(username)
            security_log.log_event(f"FTP LOGIN FAILED for '{username}': FTP error", level="WARNING")
            flash(f"FTP Server rejected login: {e}", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route("/logout")
def logout():
    if 'username' in session:
        security_log.log_audit(action="WEB_LOGOUT", user=session['username'], details="User logged out")
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for('list_files'))


@app.route('/delete', methods=['POST'])
@login_required
@csrf_protect
def delete_item():
    item_path = request.form.get('item_path')
    item_type = request.form.get('item_type')
    current_path = os.path.dirname(item_path) or '.'

    if not item_path or not item_type:
        flash("Invalid delete request.", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    try:
        item_path = sanitize_ftp_path(item_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

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
            security_log.log_audit(action="FILE_DELETE", user=session.get('username', 'unknown'),
                                   details=f"Deleted file: {item_path}")
        elif item_type == 'dir':
            local_path.rmdir()
            flash(f"Directory '{os.path.basename(item_path)}' deleted successfully.", "success")
            security_log.log_audit(action="DIR_DELETE", user=session.get('username', 'unknown'),
                                   details=f"Deleted directory: {item_path}")
    except OSError as e:
        flash(f"Could not delete item: {e}", "danger")

    return redirect(url_for('list_files', remote_path=current_path))


@app.route('/upload/<path:current_path>', methods=['POST'])
@login_required
@csrf_protect
def upload_file(current_path):
    try:
        current_path = sanitize_ftp_path(current_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    if 'file' not in request.files or request.files['file'].filename == '':
        flash("No file selected for upload.", "warning")
        return redirect(url_for('list_files', remote_path=current_path))

    file = request.files['file']

    if not validate_upload(file):
        flash("File rejected: invalid type, name, or too large.", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    try:
        safe_filename = sanitize_filename(file.filename)
    except ValueError as e:
        flash(f"File rejected: {e}", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    try:
        target_dir = get_local_path(current_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    if not target_dir.exists() or not target_dir.is_dir():
        flash(f"Directory '{current_path}' does not exist.", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    target_path = target_dir / safe_filename
    try:
        file.save(str(target_path))
        flash(f"File '{safe_filename}' uploaded successfully.", "success")
        security_log.log_audit(action="FILE_UPLOAD", user=session.get('username', 'unknown'),
                               details=f"Uploaded: {safe_filename} to {current_path}")
    except OSError as e:
        flash(f"Upload failed: {e}", "danger")

    return redirect(url_for('list_files', remote_path=current_path))


@app.route('/mkdir/<path:current_path>', methods=['POST'])
@login_required
@csrf_protect
def make_directory(current_path):
    try:
        current_path = sanitize_ftp_path(current_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    dirname = request.form.get('dirname')
    if not dirname:
        flash("Directory name cannot be empty.", "warning")
        return redirect(url_for('list_files', remote_path=current_path))

    try:
        safe_dirname = sanitize_filename(dirname)
    except ValueError as e:
        flash(f"Invalid directory name: {e}", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    try:
        target_dir = get_local_path(current_path)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    if not target_dir.exists() or not target_dir.is_dir():
        flash(f"Directory '{current_path}' does not exist.", "danger")
        return redirect(url_for('list_files', remote_path=current_path))

    new_dir = target_dir / safe_dirname
    try:
        new_dir.mkdir(exist_ok=False)
        flash(f"Directory '{safe_dirname}' created successfully.", "success")
        security_log.log_audit(action="DIR_CREATE", user=session.get('username', 'unknown'),
                               details=f"Created directory: {safe_dirname} in {current_path}")
    except OSError as e:
        flash(f"Could not create directory: {e}", "danger")

    return redirect(url_for('list_files', remote_path=current_path))


@app.route('/download/<path:filepath>')
def download_file(filepath):
    try:
        filepath = sanitize_ftp_path(filepath)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    try:
        local_path = get_local_path(filepath)
    except ValueError:
        flash("Invalid path.", "danger")
        return redirect(url_for('list_files'))

    if not local_path.exists() or not local_path.is_file():
        flash(f"File '{os.path.basename(filepath)}' not found.", "danger")
        return redirect(request.referrer or url_for('list_files'))

    security_log.log_audit(action="FILE_DOWNLOAD", user=session.get('username', 'anonymous'),
                           details=f"Downloaded: {filepath}")
    return send_file(str(local_path), as_attachment=True)


# ============================================================
# SETUP ROUTE - First-time admin user creation
# ============================================================
@app.route('/setup', methods=['GET', 'POST'])
def setup():
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

        user_db.add_user(config.ADMIN_USER, password)
        security_log.log_event(f"ADMIN USER CREATED: {config.ADMIN_USER}", level="INFO")
        security_log.log_audit(action="ADMIN_SETUP", user=config.ADMIN_USER,
                               details="Admin user created via setup")

        flash("Admin user created successfully! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('setup.html')


# ============================================================
# MAIN
# ============================================================
if __name__ == '__main__':
    start_ftp_listener_if_needed()

    print("=" * 60)
    print("  SECURE WEB FRONTEND")
    print(f"  Secret Key: Loaded from file (256-bit random)")
    print(f"  Session Lifetime: {config.PERMANENT_SESSION_LIFETIME}s")
    print(f"  Max Upload: {config.MAX_CONTENT_LENGTH // (1024*1024)}MB")
    print(f"  CSRF Protection: Enabled")
    print(f"  Rate Limiting: {config.MAX_LOGIN_ATTEMPTS} attempts / {config.LOCKOUT_DURATION // 60}min")
    print(f"  Security Headers: Enabled")
    print(f"  Audit Log: {config.AUDIT_LOG_FILE}")
    print(f"  FTP Require TLS: {config.FTP_REQUIRE_TLS}")
    print("=" * 60)
    print("  NOTE: For first run, visit http://localhost:5000/setup")
    print("        to create the admin user.")
    print("=" * 60)

    app.run(host='0.0.0.0', port=8080, debug=False)