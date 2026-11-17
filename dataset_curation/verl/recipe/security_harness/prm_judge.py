"""vLLM /classify PRM scorer for implementation guidelines (replaces LLM judge).

Scores ``(user_prompt, <high_level>+<implementation>)`` with a scalar
sequence-classification PRM (e.g. anonymous/qwen3-8b-impl-prm-exec-think).

Env (see reward_config):
  PRM_JUDGE_ENABLED, PRM_JUDGE_MODEL, PRM_JUDGE_BASE_URLS, PRM_JUDGE_MAX_LENGTH
"""

from __future__ import annotations

import math
import threading
from typing import Any

import requests

try:
    from recipe.security_harness.reward_config import (
        PRM_JUDGE_BASE_URLS,
        PRM_JUDGE_ENABLED,
        PRM_JUDGE_MAX_LENGTH,
        PRM_JUDGE_MODEL,
        PRM_JUDGE_TIMEOUT,
        debug,
    )
except ImportError:  # pragma: no cover
    from reward_config import (
        PRM_JUDGE_BASE_URLS,
        PRM_JUDGE_ENABLED,
        PRM_JUDGE_MAX_LENGTH,
        PRM_JUDGE_MODEL,
        PRM_JUDGE_TIMEOUT,
        debug,
    )

_RR = 0
_RR_LOCK = threading.Lock()


def format_chat_for_rm(prompt: str, trace: str) -> list[dict[str, str]]:
    return [
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": trace},
    ]


def guidelines_trace(high_level: str, implementation: str) -> str:
    parts: list[str] = []
    hl = (high_level or "").strip()
    im = (implementation or "").strip()
    if hl:
        parts.append(f"<high_level>\n{hl}\n</high_level>")
    if im:
        parts.append(f"<implementation>\n{im}\n</implementation>")
    return "\n\n".join(parts).strip()


def _normalize_classify_url(url: str) -> str:
    u = (url or "").rstrip("/")
    if u.endswith("/v1"):
        u = u[: -len("/v1")]
    return u


def _next_base_url() -> str:
    global _RR
    urls = PRM_JUDGE_BASE_URLS
    if not urls:
        raise RuntimeError("PRM_JUDGE_BASE_URLS is empty")
    with _RR_LOCK:
        u = urls[_RR % len(urls)]
        _RR += 1
    return _normalize_classify_url(u)


def sigmoid_prm_logit(raw: float) -> float:
    """ReCode: ``rm_score = torch.sigmoid(rm_score)`` (no temperature)."""
    x = float(raw)
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def score_guidelines_prm(
    *,
    user_prompt: str,
    model_high_level: str,
    model_implementational: str,
) -> float:
    """Return raw classify score (logit / probs[0]) for the guideline trace."""
    trace = guidelines_trace(model_high_level, model_implementational)
    if not trace.strip():
        raise ValueError("empty guideline trace for PRM")
    if not isinstance(user_prompt, str) or not user_prompt.strip():
        raise ValueError("missing user_prompt for PRM")

    messages = format_chat_for_rm(user_prompt, trace)
    root = _next_base_url()
    endpoint = f"{root}/classify"
    payload: dict[str, Any] = {
        "model": PRM_JUDGE_MODEL,
        "messages": messages,
        "add_generation_prompt": False,
        "use_activation": False,
        "truncate_prompt_tokens": int(PRM_JUDGE_MAX_LENGTH),
        "chat_template_kwargs": {"enable_thinking": False},
    }
    resp = requests.post(endpoint, json=payload, timeout=float(PRM_JUDGE_TIMEOUT))
    resp.raise_for_status()
    data = resp.json()
    items = data.get("data") or []
    if not items:
        raise RuntimeError(f"empty classify response from {endpoint}: {data}")
    probs = items[0].get("probs") or []
    if not probs:
        raise RuntimeError(f"no probs in classify response: {data}")
    return float(probs[0])


def prm_guideline_judge_score(
    *,
    cwe: str,
    user_prompt: str,
    reference_guidelines: str,
    model_high_level: str,
    model_implementational: str,
    code: str,
) -> tuple[float, float, float, float, str]:
    """Drop-in replacement for ``llm_triple_guideline_judge_score``.

    Returns ``(norm_score, b1, b2, 0.0, explanation)`` with ``b1=b2=norm_score``
    so span credit (high/impl) both receive the PRM signal.
    """
    del cwe, reference_guidelines, code
    if not PRM_JUDGE_ENABLED:
        return 0.0, 0.0, 0.0, 0.0, "[prm] disabled"
    try:
        raw = score_guidelines_prm(
            user_prompt=user_prompt,
            model_high_level=model_high_level,
            model_implementational=model_implementational,
        )
        norm = sigmoid_prm_logit(raw)
    except Exception as exc:
        debug(f"PRM judge failed: {type(exc).__name__}: {exc}")
        return 0.0, 0.0, 0.0, 0.0, f"[prm] error: {type(exc).__name__}: {exc}"

    expl = f"[prm] raw={raw:.4f} sigmoid={norm:.4f}"
    debug(f"PRM judge {expl}")
    return float(norm), float(norm), float(norm), 0.0, expl
