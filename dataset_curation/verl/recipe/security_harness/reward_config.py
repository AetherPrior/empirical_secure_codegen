"""Shared configuration and logging helpers for safe_k reward scoring."""

from __future__ import annotations

import os
import sys
from typing import Any


def env_str_list(name: str, default: str = "") -> list[str]:
    value = os.getenv(name)
    if value is None:
        value = default
    value = value.strip()
    if not value:
        return []
    if value.startswith("["):
        try:
            import json

            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except Exception:
            pass
    return [part.strip() for part in value.split(",") if part.strip()]


def env_int(name: str, default: int) -> int:
    value = os.getenv(name, str(default))
    try:
        return int(value)
    except Exception:
        return default


def env_optional_int(name: str) -> int | None:
    value = os.getenv(name)
    if value is None or not str(value).strip():
        return None
    try:
        return int(value)
    except Exception:
        return None


def env_float(name: str, default: float) -> float:
    value = os.getenv(name, str(default))
    try:
        return float(value)
    except Exception:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SECURITY_RATIO = float(os.getenv("SECURITY_RATIO", "0.5"))
USE_REAL_DETECTOR_HARNESS = env_bool("USE_REAL_DETECTOR_HARNESS", False)
UT_RATIO = float(os.getenv("UT_RATIO", "0.85"))
UNITTEST_TIMEOUT_SECONDS = float(os.getenv("UNITTEST_TIMEOUT_SECONDS", "5.0"))
REWARD_DEBUG = os.getenv("REWARD_DEBUG", "0").strip().lower() in {"1", "true", "yes", "on"}
REWARD_LOG_COMPONENTS = os.getenv("REWARD_LOG_COMPONENTS", "1").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
REWARD_DEBUG_CODE_MAX_CHARS = env_int("REWARD_DEBUG_CODE_MAX_CHARS", 1200)
# CoT / reasoning models: extract code after </thinking> (etc.). Instruct models: last fenced block.
IS_COT_MODEL = env_bool("IS_COT_MODEL", False)
LLM_JUDGE_RATIO = float(os.getenv("LLM_JUDGE_RATIO", "0.1"))

# Tokenizer for span-credit boundary alignment (see safe_k_reward._span_boundaries_from_solution).
TOKENIZER_MODEL = (
    os.getenv("TOKENIZER_MODEL") or ""
).strip()

LLM_JUDGE_ENABLED = os.getenv("LLM_JUDGE_ENABLED", "1").strip().lower() in {"1", "true", "yes", "on"}
LLM_JUDGE_MODEL = os.getenv("LLM_JUDGE_MODEL", "").strip()
LLM_JUDGE_BASE_URLS = env_str_list("LLM_JUDGE_BASE_URLS", "")
LLM_JUDGE_API_KEY = env_str_list("LLM_JUDGE_API_KEY", "")
LLM_JUDGE_API_MODE = os.getenv("LLM_JUDGE_API_MODE", "responses").strip().lower() or "responses"
LLM_JUDGE_TEMPERATURE = env_float("LLM_JUDGE_TEMPERATURE", 0.0)
LLM_JUDGE_MAX_TOKENS = env_int("LLM_JUDGE_MAX_TOKENS", 1024)
# Per-request vLLM SamplingParams thinking cap (None = omit from request).
LLM_JUDGE_THINKING_TOKEN_BUDGET = env_optional_int("LLM_JUDGE_THINKING_TOKEN_BUDGET")
GUIDELINE_CODE_ALIGNMENT_EPSILON = env_float("GUIDELINE_CODE_ALIGNMENT_EPSILON", 0.1)

# Implementation-level PRM (vLLM /classify) — replaces LLM judge when enabled.
# Only added into the reward when the rollout is fully secure AND correct
# (ReCode-style gated sum: R = exec + I(secure∧correct)·sigmoid(prm)).
PRM_JUDGE_ENABLED = env_bool("PRM_JUDGE_ENABLED", False)
PRM_JUDGE_MODEL = os.getenv(
    "PRM_JUDGE_MODEL", "anonymous/qwen3-8b-impl-prm-exec-think"
).strip()
PRM_JUDGE_BASE_URLS = env_str_list("PRM_JUDGE_BASE_URLS", "")
PRM_JUDGE_MAX_LENGTH = env_int("PRM_JUDGE_MAX_LENGTH", 2048)
PRM_JUDGE_TIMEOUT = env_float("PRM_JUDGE_TIMEOUT", 120.0)

WANDB_LOG_PREFIX = os.getenv("WANDB_LOG_PREFIX", "security_harness")

# Logged by the PPO driver via algorithm.reward_extra_log_keys (see safe_k_reward._reward_result).
REWARD_WANDB_EXTRA_KEYS = [
    "ut_score",
    "exec_score",
    "llm_judge_score",
    "llm_judge_high_level_security_relevance",
    "llm_judge_implementation_supports_high_level",
    "guideline_alignment_epsilon",
    "format_reward",
    "functionality_passed",
    "functionality_total",
    "security_passed",
    "security_total",
    "span_reward_high",
    "span_reward_impl",
    "span_reward_code",
]


def debug(msg: str) -> None:
    if REWARD_DEBUG:
        print(f"[safe_k_reward] {msg}", file=sys.stderr, flush=True)


def _format_test_fraction(passed: int | float, total: int) -> str:
    """Human-readable passed/total; total < 0 means denominator unknown (harness did not run)."""
    if total < 0:
        if isinstance(passed, (int, float)) and passed >= 0:
            if isinstance(passed, float) and not passed.is_integer():
                return f"{passed:.4g}/?"
            return f"{int(passed)}/?"
        return "n/a"
    if not isinstance(passed, (int, float)) or passed < 0:
        return f"?/{total}"
    if isinstance(passed, float) and not passed.is_integer():
        return f"{passed:.4g}/{total}"
    return f"{int(passed)}/{total}"


def log_reward_components(
    *,
    index: int = -1,
    functionality_passed: int,
    functionality_total: int,
    security_passed: float,
    security_total: int,
    ut_score: float,
    exec_score: float,
    llm_judge_score: float,
    llm_b1: float,
    llm_b2: float,
    llm_b3: float = 0.0,
    final_score: float,
    reward_failure_reason: str = "",
) -> None:
    del llm_b3  # code-consistency judge disabled; kept for call-site compatibility
    if not REWARD_LOG_COMPONENTS:
        return
    idx_s = str(index) if index >= 0 else "?"
    fail = f" failure={reward_failure_reason!r}" if reward_failure_reason else ""
    ut_s = f"{ut_score:.4f}" if ut_score >= 0 else "n/a"
    exec_s = f"{exec_score:.4f}" if exec_score >= 0 else "n/a"
    print(
        "[safe_k_reward] components "
        f"index={idx_s} "
        f"func={_format_test_fraction(functionality_passed, functionality_total)} "
        f"sec={_format_test_fraction(security_passed, security_total)} "
        f"ut={ut_s} exec={exec_s} "
        f"judge=({llm_b1},{llm_b2}) "
        f"final={final_score:.4f}"
        f"{fail}",
        file=sys.stderr,
        flush=True,
    )


def to_dict(value: Any) -> dict[str, Any] | None:
    import json

    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None
    return None


def normalize_extra_info(extra_info: Any) -> dict[str, Any]:
    details = to_dict(extra_info)
    if details is None:
        return {}

    nested = to_dict(details.get("extra_info"))
    if nested is not None:
        return nested

    return details
