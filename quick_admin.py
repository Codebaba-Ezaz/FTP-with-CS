import hashlib
import json
import os
from datetime import datetime


def generate_pbkdf2_hash(password: str, iterations: int = 1000) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=32
    )
    return f"pbkdf2:sha256:{iterations}${salt.hex()}${derived.hex()}"


def main():
    filename = "users.json"

    # 1. Load existing users if the file already exists
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                users = json.load(f)
            except json.JSONDecodeError:
                users = {}
    else:
        users = {}

    print("=== Add Users to users.json ===")

    # 2. Interactive Loop
    while True:
        username = input("\nEnter username: ").strip()

        if not username:
            print("Username cannot be empty.")
            continue

        if username in users:
            overwrite = (
                input(
                    f"User '{username}' already exists. Overwrite? (y/N): "
                )
                .strip()
                .lower()
            )
            if overwrite != "y":
                continue

        password = input("Enter password: ")
        permissions = input(
            "Enter permissions [press Enter for default 'elradfmwMT']: "
        ).strip()

        if not permissions:
            permissions = "elradfmwMT"

        # 3. Add to dictionary
        users[username] = {
            "password_hash": generate_pbkdf2_hash(password),
            "permissions": permissions,
            "created": datetime.now().isoformat(timespec="seconds"),
        }

        print(f"✓ Added '{username}'")

        # 4. Check if user wants to add another
        add_more = (
            input("\nDo you want to add another user? (y/N): ").strip().lower()
        )
        if add_more != "y":
            break

    # 5. Save everything back to users.json
    with open(filename, "w") as f:
        json.dump(users, f, indent=2)

    print(f"\nSaved updated user database to '{filename}'!")


if __name__ == "__main__":
    main()