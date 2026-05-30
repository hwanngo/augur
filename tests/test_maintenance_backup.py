"""TDD: `augur.maintenance backup` makes a consistent copy of the live DB, and
the schema is version-stamped with a downgrade guard."""
import sqlite3

import pytest

from augur.maintenance import main
from augur.auth.store import connect, SCHEMA_VERSION, init_db
from augur.auth.hashing import hash_password


def test_backup_cli_copies_the_database(tmp_path, capsys):
    db = tmp_path / "live.db"
    conn = connect(str(db))
    from augur.auth.store import UserStore
    UserStore(conn).create_user("admin1", hash_password("password1234"), "admin")

    out = tmp_path / "backup.db"
    main(["backup", "--db", str(db), "--out", str(out)])
    assert "backup" in capsys.readouterr().out.lower()
    assert out.exists()

    # The backup is a real, queryable copy with the user present.
    bk = sqlite3.connect(str(out))
    names = [r[0] for r in bk.execute("SELECT username FROM users").fetchall()]
    assert "admin1" in names
    bk.close()


def test_schema_is_version_stamped(tmp_path):
    db = tmp_path / "v.db"
    connect(str(db))
    raw = sqlite3.connect(str(db))
    assert raw.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    raw.close()


def test_newer_schema_is_refused(tmp_path):
    # An old binary must NOT silently open a DB written by a newer schema.
    db = tmp_path / "future.db"
    raw = sqlite3.connect(str(db))
    raw.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    raw.commit(); raw.close()
    with pytest.raises(RuntimeError):
        init_db(sqlite3.connect(str(db)))
