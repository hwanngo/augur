import argparse
import getpass

from augur.auth.config import load_config
from augur.auth.hashing import hash_password
from augur.auth.store import ROLES, UserStore, connect


def _password(arg: str | None) -> str:
    return arg if arg else getpass.getpass("password: ")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="augur.useradmin")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add"); a.add_argument("--username", required=True)
    a.add_argument("--role", choices=ROLES, default="analyst"); a.add_argument("--password")
    sp = sub.add_parser("set-password"); sp.add_argument("--username", required=True); sp.add_argument("--password")
    sr = sub.add_parser("set-role"); sr.add_argument("--username", required=True); sr.add_argument("--role", choices=ROLES, required=True)
    d = sub.add_parser("disable"); d.add_argument("--username", required=True)
    sub.add_parser("list")
    args = p.parse_args(argv)

    store = UserStore(connect(load_config().db_path))
    if args.cmd == "add":
        if store.get_by_username(args.username):
            raise SystemExit(f"user {args.username!r} already exists")
        store.create_user(args.username, hash_password(_password(args.password)), args.role)
        print(f"created {args.username} ({args.role})")
    elif args.cmd == "set-password":
        u = store.get_by_username(args.username) or _missing(args.username)
        store.set_password(u.id, hash_password(_password(args.password)))
        print(f"password updated for {args.username}")
    elif args.cmd == "set-role":
        u = store.get_by_username(args.username) or _missing(args.username)
        store.update_user(u.id, role=args.role); print(f"{args.username} -> {args.role}")
    elif args.cmd == "disable":
        u = store.get_by_username(args.username) or _missing(args.username)
        store.update_user(u.id, disabled=True); print(f"{args.username} disabled")
    elif args.cmd == "list":
        for u in store.list_users():
            print(f"{u.id:4} {u.username:20} {u.role:8} {'disabled' if u.disabled else 'active'}")


def _missing(username):
    raise SystemExit(f"no such user {username!r}")


if __name__ == "__main__":
    main()
