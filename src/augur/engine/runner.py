from augur.graph.interface import GraphBackend
from augur.engine.matcher import match_scenario
from augur.engine.scoring import build_detection, rank, Detection


def run_engine(backend: GraphBackend, scenarios, min_proximity: float = 0.30) -> list[Detection]:
    detections: list[Detection] = []
    for scenario in scenarios:
        matched_len, chain = match_scenario(scenario, backend)
        if matched_len > 0:
            detections.append(build_detection(scenario, matched_len, chain))
    return rank(detections, min_proximity=min_proximity)
