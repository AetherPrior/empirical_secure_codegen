"""Thin proxy to the shared simple_gen consts.

This file exists so scripts under ``simple_gen/c`` can keep importing
``from const_cwe_id_desc import ...`` when executed as standalone files (no package context).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SHARED = Path(__file__).resolve().parents[1] / "const_cwe_id_desc.py"
_SPEC = importlib.util.spec_from_file_location("_simple_gen_shared_const_cwe_id_desc", _SHARED)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"Could not load shared consts at {_SHARED}")
_MOD = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MOD)  # type: ignore[union-attr]

DEFAULT_OPENAI_BASE_URL = _MOD.DEFAULT_OPENAI_BASE_URL
CWE_ID_DESC = _MOD.CWE_ID_DESC
openai_service_tier = _MOD.openai_service_tier
