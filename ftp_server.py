import os

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
from pyftpdlib.servers import FTPServer

import config
from security_utils import security_log
from user_db import user_db


class SecureFTPHandler(TLS_FTPHandler):
    certfile = str(config.TLS_CERT_FILE)
    keyfile = str(config.TLS_KEY_FILE)
    tls_control_required = True
    tls_data_required = True

    prototype = "P"

    def on_connect(self):
        security_log.log_event(
            f"FTP CONNECTED: {self.remote_ip}:{self.remote_port}"
        )
        return super().on_connect()

    def on_disconnect(self):
        security_log.log_event(
            f"FTP DISCONNECTED: {self.remote_ip}"
        )
        return super().on_disconnect()

    def on_login(self, username):
        security_log.log_event(
            f"FTP LOGIN SUCCESS: user='{username}'"
        )
        security_log.log_audit(
            action="FTP_LOGIN",
            user=username,
            details=f"Login from {self.remote_ip}"
        )
        return super().on_login(username)

    def on_login_failed(self, username, password):
        security_log.log_event(
            f"FTP LOGIN FAILED: user='{username}' (password NOT logged)",
            level="WARNING"
        )
        return super().on_login_failed(username, password)

    def on_file_sent(self, file):
        security_log.log_audit(
            action="FTP_DOWNLOAD",
            user=self.username if hasattr(self, 'username') else 'anonymous',
            details=f"Downloaded: {file}"
        )

    def on_file_received(self, file):
        security_log.log_audit(
            action="FTP_UPLOAD",
            user=self.username if hasattr(self, 'username') else 'anonymous',
            details=f"Uploaded: {file}"
        )


class SecureAuthorizer(DummyAuthorizer):
    def has_user(self, username):
        if username in self.user_table:
            return True

        user_db.reload()

        if user_db.user_exists(username):
            ftp_root_dir = os.path.join(os.getcwd(), "ftp_root")
            user_info = user_db.get_user(username)
            perm = user_info.get("permissions", "elr") if user_info else "elr"
            self.user_table[username] = {
                "pwd": "",
                "home": os.path.realpath(ftp_root_dir),
                "perm": perm,
                "operms": {},
                "msg_login": "Login successful.",
                "msg_quit": "Goodbye.",
            }
            return True

        return False

    def validate_authentication(self, username, password, handler):
        if username == "anonymous":
            return True

        user_db.reload()

        if not user_db.user_exists(username):
            raise AuthenticationFailed("User not found")

        if not user_db.verify_credentials(username, password):
            raise AuthenticationFailed("Invalid password")

        return True


def main():
    if config.FTP_REQUIRE_TLS:
        if not (config.TLS_CERT_FILE.exists() and config.TLS_KEY_FILE.exists()):
            print("[!] TLS certificates not found!")
            print(f"    Run: python generate_cert.py")
            print(f"    Or install OpenSSL and run it manually.")
            return

    # Check if admin user exists in the database
    if not user_db.user_exists(config.ADMIN_USER):
        print(f"[*] Admin user '{config.ADMIN_USER}' not found in database.")
        print(f"[*] Please run the web app first to create the admin user.")
        print(f"    Or manually add the user by running:")
        print(f"    python -c \"from user_db import user_db; user_db.add_user('{config.ADMIN_USER}', 'your_password')\"")
        return

    authorizer = SecureAuthorizer()

    ftp_root_dir = os.path.join(os.getcwd(), "ftp_root")
    os.makedirs(ftp_root_dir, exist_ok=True)
    authorizer.add_anonymous(ftp_root_dir, perm="elr")

    for username in user_db.list_users():
        user_info = user_db.get_user(username)
        if user_info and username not in authorizer.user_table:
            authorizer.user_table[username] = {
                "pwd": "",
                "home": os.path.realpath(ftp_root_dir),
                "perm": user_info.get("permissions", "elr"),
                "operms": {},
                "msg_login": "Login successful.",
                "msg_quit": "Goodbye.",
            }

    if config.FTP_REQUIRE_TLS:
        handler = SecureFTPHandler
        handler.certfile = str(config.TLS_CERT_FILE)
        handler.keyfile = str(config.TLS_KEY_FILE)
        handler.tls_control_required = True
        handler.tls_data_required = True
        handler.prototype = "P"
        handler.banner = "Secure FTP Server (FTPS) - All connections encrypted with TLS"
        tls_status = "Enabled (control + data channels)"
    else:
        handler = FTPHandler
        handler.banner = "FTP Server (NO ENCRYPTION - credentials visible in Wireshark)"
        tls_status = "DISABLED - traffic is plaintext"

    handler.authorizer = authorizer

    port = config.FTP_TLS_PORT if config.FTP_REQUIRE_TLS else config.FTP_PORT
    address = (config.FTP_HOST, port)
    server = FTPServer(address, handler)
    server.max_cons = 256
    server.max_cons_per_ip = 5

    print(f"=" * 60)
    print(f"  FTP SERVER STARTED")
    print(f"  Address: {address[0]}:{address[1]}")
    print(f"  TLS: {tls_status}")
    if config.FTP_REQUIRE_TLS:
        print(f"  Encryption: AES-256 via TLS 1.2+")
    else:
        print(f"  WARNING: Credentials and files are NOT encrypted!")
    print(f"  Users: {', '.join(user_db.list_users())}")
    print(f"  Logs: {config.SECURITY_LOG_FILE}")
    print(f"=" * 60)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user.")
        server.close_all()


if __name__ == "__main__":
    main()