"""BaxBench evaluation arguments, bundled from the original adapter."""
from dataclasses import dataclass
from typing import Any


@dataclass
class ExtraArgs:
    agent_backend: str = "api"
    agent_api_base: str | None = None
    agent_service_tier: str | None = None
    codex_reasoning_effort: str = "none"
    claude_effort: str = "low"
    agent_max_budget_usd: float | None = None
    agent_timeout: int = 600
    reasoning_effort: str | None = None
    reasoning_summary: str = "detailed"
    service_tier: str | None = None
    max_thinking_tokens: int | None = None
    openhands_timeout: int = 300
    openhands_max_iterations: int = 50
    agent_port: int | None = None
    container: Any = None
    llm_model: str | None = None
    vllm: bool = False
    completions: bool = False
    trace_csv: str | None = None
    intervention_str: str | None = None
    custom_system_prompt: str | None = None
    no_system_prompt: bool = False
    sample_seeds: list[int] | None = None

