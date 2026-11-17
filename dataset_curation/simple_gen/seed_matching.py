from __future__ import annotations

import random
from typing import Any, Dict, List

try:
    from datasets import load_dataset
except Exception:  # pragma: no cover
    load_dataset = None  # type: ignore[misc, assignment]

_VUL2PROMPT_HF = "purpcode/vul2prompt-general-oss-26k"
_REGEX_EVAL_HF = "anonymous/RegexEval"


def normalize_cwe(value: Any) -> str:
    import re

    text = str(value or "").strip().upper()
    if not text:
        return ""
    m = re.search(r"CWE[-_ ]?(\d+)", text)
    if m:
        return f"CWE-{int(m.group(1))}"
    if text.isdigit():
        return f"CWE-{int(text)}"
    return text


def seed_cwe_accept_set(norm_cwe: str) -> List[str]:
    """Return the set of CWE IDs accepted for *seed sampling*.

    This is intentionally broader than the requested CWE to avoid sparse/absent seed rows.
    """

    if not norm_cwe:
        return []

    accept = {norm_cwe}

    # Explicit cross-CWE seed mappings.
    if norm_cwe == "CWE-113":
        accept.add("CWE-79")
    if norm_cwe == "CWE-326":
        accept.add("CWE-327")
    if norm_cwe == "CWE-347":
        accept.add("CWE-327")
    if norm_cwe == "CWE-329":
        accept.add("CWE-327")
    if norm_cwe == "CWE-760":
        # Sparse in prosecalign; borrow nearby crypto / password-hashing seeds.
        accept.add("CWE-327")
        accept.add("CWE-916")
    if norm_cwe == "CWE-943":
        accept.add("CWE-89")
    if norm_cwe == "CWE-89":
        accept.add("CWE-943")

    # Existing grouping logic used throughout the pipeline.
    if norm_cwe in ("CWE-770", "CWE-779"):
        accept.add("CWE-400")
    if norm_cwe in ("CWE-862", "CWE-863"):
        accept.add("CWE-732")
    if norm_cwe == "CWE-787":
        accept.add("CWE-119")
    if norm_cwe in ("CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-416", "CWE-476", "CWE-787"):
        accept.add("CWE-119")
    if norm_cwe in ("CWE-915",):
        accept.add("CWE-502")
    if norm_cwe in ("CWE-918",):
        accept.add("CWE-601")
    if norm_cwe in ("CWE-95",):
        accept.add("CWE-77")

    return sorted(accept)


def prosec_row_matches_cwe(row: Dict[str, Any], norm_cwe: str) -> bool:
    ecwe = str(row.get("cwe") or "").lower()
    if not ecwe:
        return False
    for cwe in seed_cwe_accept_set(norm_cwe):
        if cwe.lower() in ecwe:
            return True
    return False


def vul2prompt_row_matches_cwe(cwes: Any, norm_cwe: str) -> bool:
    accept = set(seed_cwe_accept_set(norm_cwe))
    for x in cwes or []:
        if normalize_cwe(x) in accept:
            return True
    return False


def get_cwe_description(cwe_id: Any, cwe_id_desc: dict[str, str]) -> str:
    """Look up CWE description text; tolerate ids missing from the dict."""
    norm = normalize_cwe(cwe_id)
    if norm in cwe_id_desc:
        return cwe_id_desc[norm]
    for alt in seed_cwe_accept_set(norm):
        if alt != norm and alt in cwe_id_desc:
            return cwe_id_desc[alt]
    raise KeyError(f"No CWE description for {norm!r} (tried aliases {seed_cwe_accept_set(norm)})")


def regex_eval_task_text(row: Dict[str, Any]) -> str:
    """Turn a RegexEval row into seed text for CWE-1333 task generation."""
    prompt = str(row.get("refined_prompt") or row.get("raw_prompt") or "").strip()
    expr = str(row.get("expression") or "").strip()
    parts: List[str] = []
    if prompt:
        parts.append(prompt)
    if expr:
        parts.append(f"Target regular expression: {expr}")
    matches = row.get("matches")
    non_matches = row.get("non_matches")
    if matches:
        parts.append(f"Example strings that should match: {matches}")
    if non_matches:
        parts.append(f"Example strings that should not match: {non_matches}")
    return "\n\n".join(parts)


def regex_eval_seeds(lang: str, norm_cwe: str) -> List[Dict[str, Any]]:
    """Load RegexEval rows as CWE-1333 seed text (language-agnostic; rewritten per lang)."""
    if norm_cwe != "CWE-1333":
        return []
    if load_dataset is None:
        raise RuntimeError("datasets package required for RegexEval seed loading")

    ds = load_dataset(_REGEX_EVAL_HF, split="train")
    candidates: List[Dict[str, Any]] = []
    for row in ds:
        text = regex_eval_task_text(row)
        if not text:
            continue
        candidates.append(
            {
                "task": text,
                "cwe": norm_cwe,
                "lang": lang,
                "seed_source": "regex_eval",
                "regex_eval_id": row.get("id"),
            }
        )
    return candidates


def vul2prompt_task_text(row: Dict[str, Any]) -> str:
    """Map vul2prompt `messages` to the same string role as prosec `task` / `instruction` / `prompt`."""
    msgs = row.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return ""
    user_chunks: List[str] = []
    for m in msgs:
        if not isinstance(m, dict):
            continue
        role = str(m.get("role") or "user").lower()
        if role != "user":
            continue
        c = str(m.get("content") or "").strip()
        if c:
            user_chunks.append(c)
    if user_chunks:
        return user_chunks[-1].strip()
    m0 = msgs[0]
    if isinstance(m0, dict):
        return str(m0.get("content") or "").strip()
    return ""


def fallback_vul2prompt_seeds(candidates: List[Dict[str, Any]], lang: str, norm_cwe: str) -> None:
    if candidates or not norm_cwe:
        return
    if load_dataset is None:
        return

    ds = load_dataset(_VUL2PROMPT_HF, split="train")
    for row in ds:
        if not vul2prompt_row_matches_cwe(row.get("cwes"), norm_cwe):
            continue
        text = vul2prompt_task_text(row)
        if not text:
            continue
        candidates.append({"task": text, "cwe": norm_cwe, "lang": lang, "seed_source": "vul2prompt"})


def prosecalign_seeds(dataset_name: str, lang: str, norm_cwe: str) -> List[Dict[str, Any]]:
    if load_dataset is None:
        raise RuntimeError("datasets package required for prosecalign seed loading")

    candidates: List[Dict[str, Any]] = []
    compile_time = ["java", "cpp", "c"]
    runtime = ["python", "javascript"]

    list_of_langs: List[str] = []
    if lang in compile_time:
        list_of_langs.append(lang)
        list_of_langs.extend(l for l in compile_time if l != lang)
    elif lang in runtime:
        list_of_langs.append(lang)
        list_of_langs.extend(l for l in runtime if l != lang)
    else:
        list_of_langs = [lang]

    for test_lang in list_of_langs:
        ds = load_dataset(dataset_name, split="train")
        ds_filtered = ds.filter(
            lambda e, tl=test_lang: tl.lower() in e["lang"].lower() and prosec_row_matches_cwe(e, norm_cwe)
        )
        for entry in ds_filtered:
            item = dict(entry)
            item.setdefault("seed_source", "prosecalign")
            candidates.append(item)
        if candidates:
            break

    if not candidates:
        rest_langs = [lt for lt in compile_time + runtime if lt not in list_of_langs]
        for test_lang in rest_langs:
            ds = load_dataset(dataset_name, split="train")
            ds_filtered = ds.filter(
                lambda e, tl=test_lang: tl.lower() in e["lang"].lower() and prosec_row_matches_cwe(e, norm_cwe)
            )
            for entry in ds_filtered:
                item = dict(entry)
                item.setdefault("seed_source", "prosecalign")
                candidates.append(item)
            if candidates:
                break

    return candidates


def sample_seeds(
    dataset_name: str,
    *,
    lang: str = "python",
    cwe: str = "CWE-502",
    num: int = 3,
    seed: int = 0,
    vul2prompt_langs: tuple[str, ...] = ("python",),
) -> List[Dict[str, Any]]:
    """Sample seed rows for task generation.

    CWE-1333 uses RegexEval only. Other CWEs use prosecalign with optional vul2prompt fallback.
    """
    norm_cwe = normalize_cwe(cwe)
    if not norm_cwe:
        raise ValueError(f"Invalid CWE: {cwe!r}")

    if norm_cwe == "CWE-1333":
        candidates = regex_eval_seeds(lang, norm_cwe)
        if not candidates:
            raise ValueError(
                f"No RegexEval seeds found for language {lang} and CWE {norm_cwe} "
                f"(dataset {_REGEX_EVAL_HF})."
            )
    else:
        candidates = prosecalign_seeds(dataset_name, lang, norm_cwe)
        if not candidates and lang.lower() in {x.lower() for x in vul2prompt_langs}:
            fallback_vul2prompt_seeds(candidates, lang, norm_cwe)

    if not candidates:
        raise ValueError(f"No candidates found for language {lang} and CWE {norm_cwe} in dataset {dataset_name}")

    random.seed(seed)
    if num <= 0:
        return candidates
    return random.sample(candidates, min(num, len(candidates)))
