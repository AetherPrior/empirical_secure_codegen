# Copyright 2025 Bytedance Ltd. and/or its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Utilities for span-level GRPO credit assignment."""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

import numpy as np
import torch

logger = logging.getLogger(__name__)

_SPAN_LOG_COUNTER = 0

DEFAULT_SPAN_REWARD_KEYS = ("span_reward_high", "span_reward_impl", "span_reward_code")
DEFAULT_SPAN_BOUNDARY_KEYS = ("span_high_end", "span_impl_end")

HIGH_LEVEL_CLOSE_RE = re.compile(r"</high_level>", re.IGNORECASE)
IMPL_CLOSE_RE = re.compile(r"</implementation>", re.IGNORECASE)


def get_span_config_keys(config: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Resolve span reward and boundary keys from algorithm config."""
    if config is None:
        return DEFAULT_SPAN_REWARD_KEYS, DEFAULT_SPAN_BOUNDARY_KEYS
    reward_keys = config.get("span_reward_keys", None) if hasattr(config, "get") else None
    boundary_keys = config.get("span_boundary_keys", None) if hasattr(config, "get") else None
    if reward_keys is None:
        reward_keys = DEFAULT_SPAN_REWARD_KEYS
    if boundary_keys is None:
        boundary_keys = DEFAULT_SPAN_BOUNDARY_KEYS
    return tuple(reward_keys), tuple(boundary_keys)


def _to_int_array(values: Any, batch_size: int) -> np.ndarray:
    arr = np.asarray(values, dtype=np.int64).reshape(-1)
    if arr.shape[0] != batch_size:
        raise ValueError(f"Expected batch size {batch_size}, got {arr.shape[0]}")
    return arr


def _to_float_array(values: Any, batch_size: int) -> np.ndarray:
    arr = np.asarray(values, dtype=np.float32).reshape(-1)
    if arr.shape[0] != batch_size:
        raise ValueError(f"Expected batch size {batch_size}, got {arr.shape[0]}")
    # Guard against legacy NaN defaults or partial batches breaking GRPO normalization.
    return np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)


def read_span_batch_fields(
    non_tensor_batch: dict,
    batch_size: int,
    reward_keys: tuple[str, ...],
    boundary_keys: tuple[str, ...],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Read per-sample span rewards and inclusive token end indices from non_tensor_batch."""
    for key in (*reward_keys, *boundary_keys):
        if key not in non_tensor_batch:
            raise KeyError(
                f"span_credit_assignment requires '{key}' in non_tensor_batch. "
                f"Available keys: {list(non_tensor_batch.keys())}. "
                "Ensure compute_score returns these fields in reward_extra_info."
            )
    r_high = _to_float_array(non_tensor_batch[reward_keys[0]], batch_size)
    r_impl = _to_float_array(non_tensor_batch[reward_keys[1]], batch_size)
    r_code = _to_float_array(non_tensor_batch[reward_keys[2]], batch_size)
    high_end = _to_int_array(non_tensor_batch[boundary_keys[0]], batch_size)
    impl_end = _to_int_array(non_tensor_batch[boundary_keys[1]], batch_size)
    return r_high, r_impl, r_code, high_end, impl_end


def assign_span_advantages(
    advantages: torch.Tensor,
    response_mask: torch.Tensor,
    norm_high: torch.Tensor,
    norm_impl: torch.Tensor,
    norm_code: torch.Tensor,
    high_end: np.ndarray,
    impl_end: np.ndarray,
) -> None:
    """Fill token-level advantages in-place using inclusive span end indices."""
    bsz, seq_len = advantages.shape
    valid_lens = response_mask.sum(dim=-1).to(torch.long)

    for i in range(bsz):
        valid_len = int(valid_lens[i].item())
        if valid_len <= 0:
            continue
        last_idx = valid_len - 1
        he = int(high_end[i])
        ie = int(impl_end[i])

        if he < 0 and ie < 0:
            advantages[i, :valid_len] = norm_code[i]
            continue

        he = min(he, last_idx)
        ie = min(ie, last_idx)

        if he >= 0:
            advantages[i, : he + 1] = norm_high[i]
            impl_start = he + 1
        else:
            impl_start = 0

        if ie >= impl_start:
            advantages[i, impl_start : ie + 1] = norm_impl[i]
            code_start = ie + 1
        else:
            code_start = impl_start

        if code_start <= last_idx:
            advantages[i, code_start:valid_len] = norm_code[i]

    advantages.mul_(response_mask)


def char_close_to_token_end(char_end: int, response_token_ids: list[int], tokenizer: Any) -> int:
    """Map a character offset (end of closing tag) to inclusive response token index."""
    if char_end <= 0 or not response_token_ids:
        return -1
    prefix = tokenizer.decode(response_token_ids, skip_special_tokens=False)
    if char_end >= len(prefix):
        return len(response_token_ids) - 1
    # Binary search: largest token index whose cumulative decode length <= char_end
    lo, hi = 0, len(response_token_ids) - 1
    best = -1
    while lo <= hi:
        mid = (lo + hi) // 2
        sub = tokenizer.decode(response_token_ids[: mid + 1], skip_special_tokens=False)
        if len(sub) <= char_end:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def token_ends_from_solution(
    solution_str: str,
    response_token_ids: list[int],
    tokenizer: Any,
) -> tuple[int, int]:
    """Parse XML closing tags and return inclusive token end indices (-1 if missing)."""
    high_end, impl_end = -1, -1
    hl_close = HIGH_LEVEL_CLOSE_RE.search(solution_str or "")
    if hl_close:
        high_end = char_close_to_token_end(hl_close.end(), response_token_ids, tokenizer)
    im_close = IMPL_CLOSE_RE.search(solution_str or "")
    if im_close:
        impl_end = char_close_to_token_end(im_close.end(), response_token_ids, tokenizer)
    return high_end, impl_end


def maybe_log_span_credit_sample(
    *,
    step: int = 0,
    log_interval: int,
    sample_idx: int,
    uid: Any,
    response_text: Optional[str],
    high_end: int,
    impl_end: int,
    valid_len: int,
    raw_high: float,
    raw_impl: float,
    raw_code: float,
    norm_high: float,
    norm_impl: float,
    norm_code: float,
    advantages: torch.Tensor,
    response_mask: torch.Tensor,
) -> None:
    """Log one sample's span credit assignment for debugging."""
    global _SPAN_LOG_COUNTER
    _SPAN_LOG_COUNTER += 1
    if log_interval <= 0 or (_SPAN_LOG_COUNTER % log_interval) != 0:
        return

    mask = response_mask[sample_idx].bool()
    adv = advantages[sample_idx][mask]
    he = high_end
    ie = impl_end

    def _segment_mean(start: int, end: int) -> tuple[float, int]:
        if end < start or valid_len <= 0:
            return float("nan"), 0
        end = min(end, valid_len - 1)
        seg = adv[start : end + 1]
        return float(seg.mean().item()) if seg.numel() else float("nan"), int(seg.numel())

    if he < 0 and ie < 0:
        m_code, n_code = _segment_mean(0, valid_len - 1)
        m_high, n_high = float("nan"), 0
        m_impl, n_impl = float("nan"), 0
    else:
        m_high, n_high = _segment_mean(0, he)
        impl_start = he + 1 if he >= 0 else 0
        m_impl, n_impl = _segment_mean(impl_start, ie)
        code_start = ie + 1 if ie >= impl_start else impl_start
        m_code, n_code = _segment_mean(code_start, valid_len - 1)

    text_preview = ""
    if response_text is not None:
        text_preview = response_text[:500] + ("..." if len(response_text) > 500 else "")

    logger.info(
        "[span_credit] step=%s uid=%s sample=%s\n"
        "response: %s\n"
        "boundaries (inclusive): high_end=%s impl_end=%s valid_len=%s\n"
        "raw: r_high=%.4f r_impl=%.4f r_code=%.4f\n"
        "norm: A_high=%.4f A_impl=%.4f A_code=%.4f\n"
        "mean_adv: high=%.4f (%s tok) impl=%.4f (%s tok) code=%.4f (%s tok)",
        step,
        uid,
        sample_idx,
        text_preview,
        he,
        ie,
        valid_len,
        raw_high,
        raw_impl,
        raw_code,
        norm_high,
        norm_impl,
        norm_code,
        m_high,
        n_high,
        m_impl,
        n_impl,
        m_code,
        n_code,
    )
