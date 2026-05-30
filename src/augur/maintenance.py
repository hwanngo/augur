"""
Maintenance CLI for Augur.

Usage:
    python -m augur.maintenance prune [--days N] [--db PATH]

Environment:
    AUGUR_RETENTION_DAYS  retention window in days (default 90)
    AUGUR_DB              path to the sqlite database (default data/augur.db)
"""
import argparse
import os
from datetime import datetime, timedelta, timezone


def _resolve_cutoff(days: int) -> str:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    return cutoff.isoformat()


def _do_prune(db_path: str, days: int) -> None:
    from augur.auth.store import connect, SessionStore, AuthEvents
    from augur.alerting.store import AlertStore
    from augur.generative.candidates import CandidateStore

    cutoff = _resolve_cutoff(days)
    conn = connect(db_path)

    sessions_deleted = SessionStore(conn).prune_expired(cutoff)
    events_deleted = AuthEvents(conn).prune(cutoff)
    alerts_deleted = AlertStore(conn).prune(cutoff)
    candidates_deleted = CandidateStore(conn).prune(cutoff)

    print(
        f"pruned: sessions={sessions_deleted} auth_events={events_deleted} "
        f"alerts={alerts_deleted} candidates={candidates_deleted}"
    )


def _do_backup(db_path: str, out_path: str) -> None:
    import sqlite3
    from pathlib import Path

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(db_path)
    dst = sqlite3.connect(out_path)
    try:
        with dst:                       # sqlite online backup: consistent snapshot, WAL-safe
            src.backup(dst)
    finally:
        src.close()
        dst.close()
    print(f"backup written: {out_path}")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="augur.maintenance",
                                     description="Augur maintenance tasks")
    sub = parser.add_subparsers(dest="command", required=True)

    prune_parser = sub.add_parser("prune", help="Delete old records from all stores")
    prune_parser.add_argument(
        "--days", type=int,
        default=int(os.environ.get("AUGUR_RETENTION_DAYS", "90")),
        help="Retain records newer than N days (default: 90 or AUGUR_RETENTION_DAYS)",
    )
    prune_parser.add_argument(
        "--db",
        default=os.environ.get("AUGUR_DB", "data/augur.db"),
        help="Path to sqlite database (default: data/augur.db or AUGUR_DB)",
    )

    backup_parser = sub.add_parser("backup", help="Write a consistent copy of the DB")
    backup_parser.add_argument(
        "--db",
        default=os.environ.get("AUGUR_DB", "data/augur.db"),
        help="Path to sqlite database (default: data/augur.db or AUGUR_DB)",
    )
    backup_parser.add_argument(
        "--out", required=True,
        help="Destination path for the backup copy",
    )

    args = parser.parse_args(argv)
    if args.command == "prune":
        _do_prune(args.db, args.days)
    elif args.command == "backup":
        _do_backup(args.db, args.out)


if __name__ == "__main__":
    main()
