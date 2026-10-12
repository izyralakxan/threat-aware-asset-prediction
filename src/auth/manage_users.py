"""
User administration from the command line (run from the project root).

    python -m src.auth.manage_users init-demo          demo users + asset ownership
    python -m src.auth.manage_users list
    python -m src.auth.manage_users create USERNAME --role analyst --name "Full Name" [--email ..] [--team ..]
    python -m src.auth.manage_users reset-password USERNAME
    python -m src.auth.manage_users reset-mfa USERNAME
    python -m src.auth.manage_users unlock USERNAME

New and reset accounts get a random temporary password. At the first sign-in
the user must choose a new password and set up an authenticator app (MFA).
"""

import argparse

from src.auth import store
from src.auth.rbac import ROLES
from src.auth.security import hash_password, temporary_password

DEMO_USERS = [
    ("admin", "System Administrator", "admin", "it-admin@company.local", ""),
    ("manager", "Security Manager", "security_manager", "security-manager@company.local", ""),
    ("analyst", "Security Analyst", "analyst", "soc@company.local", ""),
    ("webteam", "Web Team Lead", "asset_owner", "web-team@company.local", "Web team"),
    ("auditor", "Internal Auditor", "auditor", "audit@company.local", ""),
]

# Team ownership of assets: (lab, team, team email, asset ids)
DEMO_OWNERS = [
    ("lab_environment.db", "Web team", "web-team@company.local", ["L003", "L004", "L005", "L007", "L008"]),
    ("lab_environment.db", "Infrastructure team", "infra-team@company.local", ["L001", "L002", "L019", "L020", "L030"]),
    ("lab_environment.db", "Windows server team", "windows-team@company.local", ["L006", "L010", "L011", "L012", "L013"]),
    ("lab_environment.db", "Application and database team", "apps-db-team@company.local", ["L014", "L015", "L016", "L017", "L018"]),
    ("lab_environment.db", "IT service desk", "service-desk@company.local", [f"L1{n:02d}" for n in range(1, 11)]),
    ("vmware_lab.db", "Web team", "web-team@company.local", ["V010"]),
    ("vmware_lab.db", "Infrastructure team", "infra-team@company.local", ["V001", "V002"]),
    ("vmware_lab.db", "Windows server team", "windows-team@company.local", ["V020"]),
    ("vmware_lab.db", "Application and database team", "apps-db-team@company.local", ["V021"]),
    ("vmware_lab.db", "IT service desk", "service-desk@company.local", ["V030"]),
]


def issue_password(username, actor="cli"):
    password = temporary_password()
    store.update_user(username, password_hash=hash_password(password), must_change_password=1,
                      failed_attempts=0, locked_until=None)
    store.audit("password_reset", actor, None, f"temporary password issued for {username}")
    return password


def main():
    parser = argparse.ArgumentParser(description="Manage dashboard users")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-demo")
    sub.add_parser("list")
    create = sub.add_parser("create")
    create.add_argument("username")
    create.add_argument("--role", required=True, choices=list(ROLES))
    create.add_argument("--name", required=True)
    create.add_argument("--email", default="")
    create.add_argument("--team", default="")
    for name in ["reset-password", "reset-mfa", "unlock"]:
        sub.add_parser(name).add_argument("username")

    args = parser.parse_args()

    if args.command == "init-demo":
        created = []
        for username, name, role, email, team in DEMO_USERS:
            if store.get_user(username):
                print(f"  {username}: already exists, unchanged")
                continue
            password = temporary_password()
            store.create_user(username, name, role, hash_password(password), email, team)
            store.audit("user_created", "cli", None, f"{username} ({role})")
            created.append((username, ROLES[role], password))
        for lab, team, email, assets in DEMO_OWNERS:
            for asset in assets:
                store.set_owner(lab, asset, team, email)
        print("\nDemo accounts (temporary passwords: change and set up MFA at first sign-in):\n")
        for username, role, password in created:
            print(f"  {username:<10} {role:<18} {password}")
        print("\nAsset ownership assigned for the synthetic lab and the VMware lab.")

    elif args.command == "list":
        print(store.list_users().to_string(index=False))

    elif args.command == "create":
        if store.get_user(args.username):
            raise SystemExit(f"User {args.username} already exists")
        password = temporary_password()
        store.create_user(args.username, args.name, args.role, hash_password(password),
                          args.email, args.team)
        store.audit("user_created", "cli", None, f"{args.username} ({args.role})")
        print(f"Created {args.username} ({ROLES[args.role]}). Temporary password: {password}")

    else:
        if not store.get_user(args.username):
            raise SystemExit(f"No such user: {args.username}")
        if args.command == "reset-password":
            print(f"Temporary password for {args.username}: {issue_password(args.username)}")
        elif args.command == "reset-mfa":
            store.update_user(args.username, totp_secret=None, mfa_enabled=0, last_totp_counter=None)
            store.audit("mfa_reset", "cli", None, args.username)
            print(f"MFA reset for {args.username}: they will enrol again at next sign-in")
        elif args.command == "unlock":
            store.update_user(args.username, failed_attempts=0, locked_until=None)
            store.audit("account_unlocked", "cli", None, args.username)
            print(f"{args.username} unlocked")


if __name__ == "__main__":
    main()
