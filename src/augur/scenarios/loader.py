from pathlib import Path
import yaml
from augur.scenarios.schema import Scenario


def load_scenario(path: str | Path) -> Scenario:
    data = yaml.safe_load(Path(path).read_text())
    try:
        return Scenario(**data)
    except Exception as e:  # re-raise with file context
        raise ValueError(f"invalid scenario {path}: {e}") from e


def load_scenarios(directory: str | Path) -> list[Scenario]:
    """Recursively load every *.yaml under ``directory`` (supports category subfolders).

    Raises ValueError on duplicate scenario_ids so collisions surface immediately.
    """
    directory = Path(directory)
    files = sorted(directory.rglob("*.yaml"))
    scenarios = [load_scenario(f) for f in files]
    seen: dict[str, Path] = {}
    for f, s in zip(files, scenarios):
        if s.scenario_id in seen:
            raise ValueError(
                f"duplicate scenario_id {s.scenario_id} in {f} (also in {seen[s.scenario_id]})"
            )
        seen[s.scenario_id] = f
    return sorted(scenarios, key=lambda s: s.scenario_id)
