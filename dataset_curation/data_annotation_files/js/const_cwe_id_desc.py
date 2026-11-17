"""JS annotation constants — CWE descriptions for js_cwe_GRPO rewrite audits."""

from __future__ import annotations

import os
import sys
from pathlib import Path

DEFAULT_OPENAI_BASE_URL = "https://us.api.openai.com/v1"


def openai_service_tier(default: str = "flex") -> str:
    return (os.getenv("OPENAI_SERVICE_TIER") or default).strip() or default


# Prefer shared simple_gen descriptions when available.
_SIMPLE_GEN = Path(__file__).resolve().parents[2] / "simple_gen"
if str(_SIMPLE_GEN) not in sys.path:
    sys.path.insert(0, str(_SIMPLE_GEN))

try:
    from const_cwe_id_desc import (  # type: ignore
        CWE_ID_DESC as _SHARED,
        JS_DATA_GEN_MODEL,
        enforce_openai_model,
    )
except Exception:
    _SHARED = {}
    JS_DATA_GEN_MODEL = "gpt-5.4-mini"

    def enforce_openai_model(model: str, *, required: str = JS_DATA_GEN_MODEL) -> str:
        chosen = (model or "").strip()
        if chosen != required:
            raise SystemExit(f"Only model {required!r} is supported for this pipeline (got {chosen!r})")
        return required

# JS GRPO set (+ XPath / extended generation CWEs).
_JS_EXTRA = {
    "CWE-643": (
        "CWE-643: Improper Neutralization of Data within XPath Expressions "
        "('XPath Injection'). User-controlled strings are interpolated into XPath "
        "queries so attackers can alter query logic, bypass auth, or exfiltrate nodes."
    ),
    "CWE-760": (
        "CWE-760: Use of a One-Way Hash without a Salt. The function hashes passwords "
        "or similar secrets with a missing, constant, or otherwise predictable salt."
    ),
}

CWE_ID_DESC = {**_SHARED, **_JS_EXTRA}
