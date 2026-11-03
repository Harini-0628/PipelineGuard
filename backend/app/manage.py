"""Administrative CLI:  python -m app.manage create-user --email a@b.c --role admin  (password prompted)"""
from __future__ import annotations

import argparse
import getpass
import sys

from app.db import session_factory
from app.models import Role
from app.bootstrap import create_user
from app.services.policy_store import seed_default_policy


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.manage")
    sub = p.add_subparsers(dest="cmd", required=True)
    cu = sub.add_parser("create-user")
    cu.add_argument("--email", required=True)
    cu.add_argument("--role", choices=[r.value for r in Role], default="admin")
    cu.add_argument("--name", default="")
    sub.add_parser("seed-policy")
    args = p.parse_args(argv)
    with session_factory()() as db:
        if args.cmd == "create-user":
            pw = getpass.getpass("Password (min 12 chars, mixed case + digit): ")
            if pw != getpass.getpass("Repeat password: "):
                print("passwords do not match", file=sys.stderr)
                return 1
            try:
                create_user(db, args.email, pw, Role(args.role), args.name)
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 1
            print(f"created {args.role} {args.email}")
        elif args.cmd == "seed-policy":
            seed_default_policy(db)
            print("default policy present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
