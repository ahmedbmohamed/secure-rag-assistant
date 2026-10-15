"""Create the demo accounts and print their secrets once.

    python scripts/create_users.py

People (admin, user1, user2) sign in to the web page with a password, then set up MFA with an
authenticator app at their first sign-in. Service accounts use an API key, for scripts only.
"""

from srag.auth import create_demo_accounts
from srag.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
    if settings.users_file.exists():
        answer = input(f"{settings.users_file} exists. Replace every account? Type yes: ")
        if answer.strip().lower() != "yes":
            raise SystemExit("Nothing changed.")
    shown = create_demo_accounts(settings.users_file)
    print(f"Accounts written to {settings.users_file} (only hashes are stored).\n")
    print("Web sign-in (username / password). MFA is set up at the first sign-in:")
    print(f"  admin  (user management)          {shown['admin']}")
    print(f"  user1  (staff)                    {shown['user1']}")
    print(f"  user2  (staff, security-admin)    {shown['user2']}")
    print("\nAPI keys for scripts (X-API-Key header), no web sign-in:")
    print(f"  svc-eval-staff                    {shown['svc-eval-staff']}")
    print(f"  svc-eval-admin                    {shown['svc-eval-admin']}")
    print("\nKeep these values now: they are not stored and cannot be shown again.")
