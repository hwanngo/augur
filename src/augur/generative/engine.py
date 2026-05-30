from augur.generative.base import GenerationRequest, ScenarioGenerator
from augur.generative.gauntlet import run_gauntlet, GauntletResult, _fingerprint
from augur.scenarios.schema import Scenario
import yaml as _yaml


def generate_candidates(
    request: GenerationRequest,
    generator: ScenarioGenerator,
    existing: list[Scenario],
    store=None,
    created_by: str = "cli",
) -> list[GauntletResult]:
    """Generate n candidates, run them through the gauntlet, store passers, return all results.

    Intra-batch deduplication: scenario_ids and fingerprints of each passer are
    threaded into subsequent ``run_gauntlet`` calls so no two candidates in the
    same batch get the same id (C2) or the same structural fingerprint (I1).
    """
    raw_yamls = generator.generate(request, request.n)
    results: list[GauntletResult] = []
    batch_used_ids: set[str] = set()
    batch_fingerprints: set[tuple] = set()

    for y in raw_yamls:
        result = run_gauntlet(
            y, existing,
            extra_used=batch_used_ids,
            extra_fingerprints=batch_fingerprints,
        )
        results.append(result)
        if result.passed:
            # Record this passer's id and fingerprint for subsequent candidates.
            batch_used_ids.add(result.scenario_id)
            # Re-parse the canonical yaml to get the fingerprint.
            try:
                data = _yaml.safe_load(result.yaml)
                scenario = Scenario(**data)
                batch_fingerprints.add(_fingerprint(scenario))
            except Exception:
                pass  # defensive; fingerprint miss is non-fatal (dedup may just miss)

            if store is not None:
                from augur.generative.candidates import Candidate
                import json
                store.create(Candidate(
                    scenario_id=result.scenario_id,
                    category=_infer_category(request),
                    yaml=result.yaml,
                    seed_id=request.seed_id or "",
                    mutation_axes=",".join(request.axes) if request.axes else "",
                    plausibility=result.plausibility,
                    gauntlet_report=json.dumps({"notes": result.notes}),
                    created_by=created_by,
                ))
    return results


def _infer_category(request: GenerationRequest) -> str:
    if request.category:
        return request.category
    if request.seed_id:
        # Try to find category from scenario library by searching yaml paths
        from pathlib import Path
        import os
        scenarios_dir = Path(os.getcwd()) / "scenarios"
        if not scenarios_dir.exists():
            # Try relative to package root
            scenarios_dir = Path(__file__).resolve().parents[3] / "scenarios"
        if scenarios_dir.exists():
            for cat_dir in scenarios_dir.iterdir():
                if cat_dir.is_dir():
                    for f in cat_dir.glob("*.yaml"):
                        import yaml
                        try:
                            data = yaml.safe_load(f.read_text())
                            if (data.get("scenario_metadata", {}) or {}).get("scenario_id") == request.seed_id:
                                return cat_dir.name
                        except Exception:
                            pass
    return "generated"
