"""Create the two demo users and print their API keys once.

python scripts/create_users.py
"""

from srag.auth import create_demo_users
from srag.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
    keys = create_demo_users(settings.users_file)
    print(f"Users written to {settings.users_file} (only key hashes are stored).")
    print("user1 (staff):                 ", keys["user1"])
    print("user2 (staff, security-admin): ", keys["user2"])
    print("Keep these keys: they are not stored and cannot be shown again.")
