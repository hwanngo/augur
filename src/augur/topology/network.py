from pathlib import Path
import yaml
from pydantic import BaseModel, ConfigDict
from augur.enums import Zone, Criticality


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostname: str
    zone: Zone
    criticality: Criticality
    os: str
    ip: str
    role: str | None = None


class Topology(BaseModel):
    model_config = ConfigDict(extra="forbid")
    zones: list[Zone]
    assets: list[Asset]

    def lookup(self, hostname: str) -> Asset | None:
        key = hostname.lower()
        for a in self.assets:
            if a.hostname.lower() == key:
                return a
        return None

    def enrich(self, hostname: str) -> tuple[Zone, Criticality]:
        a = self.lookup(hostname)
        if a is None:
            return Zone.Unknown, Criticality.UNKNOWN
        return a.zone, a.criticality


def load_topology(path: str | Path) -> Topology:
    data = yaml.safe_load(Path(path).read_text())
    return Topology(**data)
