"""Opt-in Claude LLM scenario generator.

`anthropic` is imported LAZILY inside __init__ so the default test suite never
imports it (and it doesn't need to be installed).

Activate with:
    AUGUR_AI_GENERATOR=claude ANTHROPIC_API_KEY=sk-... uv run python -m augur.generate ...
"""
import re

import yaml

from augur.generative.base import GenerationRequest
from augur.generative.config import load_ai_config
from augur.generative.prompt import build_system_prompt, build_user_prompt
from augur.scenarios.loader import load_scenarios
from augur.pipeline import default_topology


def _find_seed_yaml(seed_id: str) -> str | None:
    """Look up a seed scenario by id and return its YAML string, or None."""
    from pathlib import Path
    import os
    scenarios_dir = Path(os.getcwd()) / "scenarios"
    if not scenarios_dir.exists():
        from augur.generate import __file__ as _gf
        scenarios_dir = Path(_gf).resolve().parents[3] / "scenarios"
    try:
        scenarios = load_scenarios(scenarios_dir)
        for s in scenarios:
            if s.scenario_id == seed_id:
                return yaml.safe_dump(s.model_dump(mode="json"), sort_keys=False)
    except Exception:
        pass
    return None


def _parse_yaml_candidates(text: str) -> list[str]:
    """Extract YAML document strings from an LLM response.

    Handles:
    - Markdown code fences (```yaml ... ```)
    - YAML document separators (--- between docs)
    - Leading prose before the first ``scenario_metadata:`` line

    The first thing in each returned string is always ``scenario_metadata:``.
    """
    # Strip markdown code fences
    text = re.sub(r"```(?:yaml)?\n?", "", text)
    text = re.sub(r"```\n?", "", text)
    # Split on yaml document separators
    docs = re.split(r"\n---\n", text)
    results = []
    for doc in docs:
        doc = doc.strip()
        if not doc or "scenario_metadata" not in doc:
            continue
        # Strip any leading prose lines that appear before 'scenario_metadata:'
        # Find the first line that starts with 'scenario_metadata'
        lines = doc.splitlines()
        start_idx = next(
            (i for i, line in enumerate(lines) if line.strip().startswith("scenario_metadata")),
            None,
        )
        if start_idx is not None:
            doc = "\n".join(lines[start_idx:]).strip()
        if doc:
            results.append(doc)
    return results if results else [text.strip()]


class ClaudeScenarioGenerator:
    """LLM-backed scenario generator using the Anthropic Messages API with prompt caching."""

    def __init__(self) -> None:
        try:
            import anthropic  # lazy — fails fast if [ai] extra not installed
        except ImportError as e:
            raise ImportError(
                "The 'anthropic' package is required for ClaudeScenarioGenerator. "
                "Install it with: uv pip install 'augur[ai]'"
            ) from e

        self._anthropic = anthropic
        self._cfg = load_ai_config()
        if not self._cfg.api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable is not set. "
                "Set it before using the 'claude' generator."
            )
        self._client = anthropic.Anthropic(api_key=self._cfg.api_key)
        self._system_prompt = build_system_prompt()

    def generate(self, request: GenerationRequest, n: int) -> list[str]:
        """Call the Claude API and return a list of raw YAML strings."""
        # Resolve seed YAML
        seed_yaml = ""
        if request.seed_id:
            seed_yaml = _find_seed_yaml(request.seed_id) or f"# seed: {request.seed_id}\n"

        req = GenerationRequest(
            seed_id=request.seed_id,
            category=request.category,
            technique=request.technique,
            n=n,
            axes=request.axes,
        )
        user_prompt = build_user_prompt(req, seed_yaml)

        # Use cache_control on the (large, stable) system block for prompt caching
        response = self._client.messages.create(
            model=self._cfg.model,
            max_tokens=self._cfg.max_tokens,
            temperature=self._cfg.temperature,
            system=[
                {
                    "type": "text",
                    "text": self._system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[
                {"role": "user", "content": user_prompt}
            ],
        )

        raw_text = response.content[0].text if response.content else ""
        return _parse_yaml_candidates(raw_text)
