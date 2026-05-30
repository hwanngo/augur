from augur.normalize.model import NormalizedEvent, _ext


def test_normalized_event_new_optional_fields_default_none():
    e = NormalizedEvent(timestamp=None, kind="process_create", host="h", event_id=1)
    assert e.source_type is None and e.os_family is None and e.raw_event_type is None
    # existing fields still default as before
    assert e.is_injected is False and e.hashes == {} and e.hooked_functions == []


def test_ext_handles_windows_and_posix_and_none():
    assert _ext("C:\\x\\evil.DLL") == ".dll"
    assert _ext("/tmp/.evil.so") == ".so"
    assert _ext("/usr/bin/curl") == ""
    assert _ext(None) is None
