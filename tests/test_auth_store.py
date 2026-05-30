from augur.auth.store import connect, UserStore, SessionStore, AuthEvents, role_rank


def _stores(tmp_path):
    conn = connect(str(tmp_path / "t.db"))
    return UserStore(conn), SessionStore(conn), AuthEvents(conn)


def test_user_crud_and_roles(tmp_path):
    us, _, _ = _stores(tmp_path)
    assert us.is_empty() is True
    uid = us.create_user("Alice", "hash1", "admin")
    u = us.get_by_username("alice")           # case-insensitive
    assert u.id == uid and u.role == "admin" and u.disabled is False
    assert us.count_admins() == 1             # enabled admin counts
    us.update_user(uid, disabled=True)
    assert us.get_by_id(uid).disabled is True
    us.set_password(uid, "hash2")
    assert us.get_by_id(uid).password_hash == "hash2"
    assert us.count_admins() == 0             # disabled admin does NOT count (last-admin guard)
    assert [x.username for x in us.list_users()] == ["Alice"]
    us.delete_user(uid)
    assert us.get_by_id(uid) is None


def test_session_lifecycle_and_cascade(tmp_path):
    us, ss, _ = _stores(tmp_path)
    uid = us.create_user("bob", "h", "viewer")
    s = ss.create_session(uid)
    assert s.csrf_token and ss.get(s.id).user_id == uid
    ss.touch(s.id)
    ss.delete(s.id); assert ss.get(s.id) is None
    s2 = ss.create_session(uid)
    us.delete_user(uid)                       # FK cascade removes sessions
    assert ss.get(s2.id) is None


def test_role_rank_order():
    assert role_rank("viewer") < role_rank("analyst") < role_rank("admin")


def test_audit_log(tmp_path):
    _, _, ev = _stores(tmp_path)
    ev.log("login_failed", username="x", ip="1.2.3.4", detail="bad pw")
    rows = ev.recent(10)
    assert rows and rows[0]["event"] == "login_failed"
