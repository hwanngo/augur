from augur.useradmin import main
from augur.auth.store import connect, UserStore


def test_cli_add_and_list(tmp_path, monkeypatch, capsys):
    db = str(tmp_path / "c.db")
    monkeypatch.setenv("AUGUR_ENV", "test")
    monkeypatch.setenv("AUGUR_DB", db)
    main(["add", "--username", "root", "--role", "admin", "--password", "password1234"])
    us = UserStore(connect(db))
    u = us.get_by_username("root")
    assert u and u.role == "admin"
    main(["list"])
    assert "root" in capsys.readouterr().out
