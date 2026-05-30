"""Determinism gate: the streaming/eviction code must contain no wall-clock or randomness — the cutoff
derives only from ingested event timestamps. Mirrors the scoring-path AST guard."""
import ast
import pathlib

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "augur"
_FILES = [_SRC / "streaming" / "graph.py", _SRC / "graph" / "eviction.py", _SRC / "graph" / "builder.py"]


def test_no_wallclock_or_randomness_in_streaming_and_eviction():
    for py in _FILES:
        tree = ast.parse(py.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name.split(".")[0] not in {"random", "secrets", "time"}, \
                        f"{py.name} imports forbidden module {a.name}"
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in {"random", "secrets", "time"}, \
                    f"{py.name} imports from forbidden module {node.module}"
            elif isinstance(node, ast.Attribute):
                assert node.attr not in {"now", "utcnow"}, f"{py.name} calls .{node.attr}() (no wall-clock)"
