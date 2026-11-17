"""
CoSec co-decoding generation using rejection sampling.

Works with any AutoModelForCausalLM (Qwen3, CodeLlama, Codegen, etc.)
without depending on transformers internal APIs.

Usage:
    from cosec_generate import cosec_sample

    outputs = cosec_sample(
        target_model=target_model,
        expert_model=expert_model,
        input_ids=input_ids,
        max_new_tokens=256,
        temperature=0.4,
        top_p=0.95,
        threshold=0.3,
        num_return_sequences=1,
        pad_token_id=tokenizer.pad_token_id,
        eos_token_id=tokenizer.eos_token_id,
    )
"""

from typing import List, Optional, Union
import ast

import torch
import torch.nn.functional as F


def _is_complete_function(token_ids: torch.LongTensor, tokenizer) -> bool:
    """Return True if the decoded tokens form at least one syntactically complete function."""
    try:
        text = tokenizer.decode(token_ids, skip_special_tokens=True)
    except Exception:
        return False
    # must contain a function definition
    if 'def ' not in text:
        return False
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    # check at least one complete FunctionDef exists
    return any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree))


def _top_p_filter(logits: torch.Tensor, top_p: float) -> torch.Tensor:
    sorted_logits, sorted_indices = torch.sort(logits, descending=True, dim=-1)
    cumulative_probs = torch.cumsum(F.softmax(sorted_logits, dim=-1), dim=-1)
    sorted_indices_to_remove = cumulative_probs - F.softmax(sorted_logits, dim=-1) > top_p
    sorted_logits[sorted_indices_to_remove] = float("-inf")
    logits = torch.zeros_like(logits).scatter_(-1, sorted_indices, sorted_logits)
    return logits


def _apply_temperature_and_top_p(
    logits: torch.Tensor, temperature: float, top_p: float
) -> torch.Tensor:
    if temperature > 0:
        logits = logits / temperature
    if top_p < 1.0:
        logits = _top_p_filter(logits, top_p)
    return logits


@torch.no_grad()
def cosec_sample(
    target_model: torch.nn.Module,
    expert_model: torch.nn.Module,
    input_ids: torch.LongTensor,
    max_new_tokens: int = 256,
    temperature: float = 0.4,
    top_p: float = 0.95,
    expert_temperature: float = 0.4,
    expert_top_p: float = 0.95,
    threshold: float = 0.3,
    num_return_sequences: int = 1,
    pad_token_id: Optional[int] = None,
    eos_token_id: Optional[Union[int, list]] = None,
    tokenizer=None,
    stop_on_complete_function: bool = False,
    stop_strings: Optional[List[str]] = None,
) -> torch.LongTensor:
    """
    CoSec rejection-sampling co-decoding.

    At each step:
      1. expert proposes a token from expert distribution
      2. accept if threshold < min(1, p_lm(t) / p_exp(t))
      3. if rejected, fall back to sampling from target (lm) distribution

    Args:
        target_model: base LM (e.g. Qwen3-8B AutoModelForCausalLM)
        expert_model: security-tuned LM (e.g. PeftModel with LoRA)
        input_ids: (1, seq_len) prompt token ids
        threshold: acceptance threshold (default 0.3 from CoSec paper)
        num_return_sequences: number of independent samples to generate

    Returns:
        (num_return_sequences, seq_len + max_new_tokens) generated token ids
    """
    if isinstance(eos_token_id, int):
        eos_token_id = [eos_token_id]

    device = input_ids.device
    batch_size = input_ids.shape[0]
    assert batch_size == 1, "input_ids batch_size must be 1; use num_return_sequences for multiple samples"

    # expand input for num_return_sequences
    input_ids = input_ids.expand(num_return_sequences, -1).clone()  # (N, seq_len)
    prompt_len = input_ids.shape[1]

    unfinished = torch.ones(num_return_sequences, dtype=torch.long, device=device)

    # KV cache state
    past_target = None
    past_expert = None

    for _ in range(max_new_tokens):
        # --- target model forward ---
        target_out = target_model(
            input_ids=input_ids if past_target is None else input_ids[:, -1:],
            past_key_values=past_target,
            use_cache=True,
        )
        past_target = target_out.past_key_values
        lm_logits = target_out.logits[:, -1, :]  # (N, vocab)

        # --- expert model forward ---
        expert_out = expert_model(
            input_ids=input_ids if past_expert is None else input_ids[:, -1:],
            past_key_values=past_expert,
            use_cache=True,
        )
        past_expert = expert_out.past_key_values
        exp_logits = expert_out.logits[:, -1, :]  # (N, vocab)

        # cast to float32 before any arithmetic to avoid fp16 overflow
        lm_logits = lm_logits.float()
        exp_logits = exp_logits.float()

        # --- expert: apply temperature + top_p, then sample proposed token ---
        exp_logits_w = _apply_temperature_and_top_p(exp_logits.clone(), expert_temperature, expert_top_p)
        exp_logits_w = exp_logits_w - exp_logits_w.amax(dim=-1, keepdim=True)
        exp_probs = F.softmax(exp_logits_w, dim=-1)  # (N, vocab)
        exp_probs = torch.nan_to_num(exp_probs, nan=0.0, posinf=0.0, neginf=0.0).clamp(min=0.0)
        exp_probs = exp_probs / exp_probs.sum(dim=-1, keepdim=True).clamp(min=1e-10)

        # --- expert proposes token ---
        exp_token = torch.multinomial(exp_probs, num_samples=1)  # (N, 1)

        # --- lm: raw logits for acceptance ratio (no temperature/top_p), matching original CoSec ---
        lm_logits_raw = lm_logits - lm_logits.amax(dim=-1, keepdim=True)
        lm_probs_raw = F.softmax(lm_logits_raw, dim=-1)
        lm_probs_raw = torch.nan_to_num(lm_probs_raw, nan=0.0, posinf=0.0, neginf=0.0).clamp(min=0.0)
        lm_probs_raw = lm_probs_raw / lm_probs_raw.sum(dim=-1, keepdim=True).clamp(min=1e-10)

        # --- rejection sampling acceptance: p_lm(raw) / p_exp(sharpened) ---
        p_lm_at_exp = torch.gather(lm_probs_raw, 1, exp_token).squeeze(1)   # (N,)
        p_exp_at_exp = torch.gather(exp_probs, 1, exp_token).squeeze(1)      # (N,)

        acceptance_prob = torch.clamp(p_lm_at_exp / (p_exp_at_exp + 1e-10), max=1.0)
        accept = (torch.ones(num_return_sequences, device=device) * threshold) < acceptance_prob  # (N,)

        # --- fallback: sample from lm with temperature + top_p ---
        lm_logits_w = _apply_temperature_and_top_p(lm_logits.clone(), temperature, top_p)
        lm_logits_w = lm_logits_w - lm_logits_w.amax(dim=-1, keepdim=True)
        lm_probs = F.softmax(lm_logits_w, dim=-1)
        lm_probs = torch.nan_to_num(lm_probs, nan=0.0, posinf=0.0, neginf=0.0).clamp(min=0.0)
        lm_probs = lm_probs / lm_probs.sum(dim=-1, keepdim=True).clamp(min=1e-10)
        lm_token = torch.multinomial(lm_probs, num_samples=1)  # (N, 1)

        next_tokens = torch.where(accept.unsqueeze(1), exp_token, lm_token)  # (N, 1)
        next_tokens = next_tokens.squeeze(1)  # (N,)

        # pad finished sequences
        if eos_token_id is not None:
            if pad_token_id is None:
                raise ValueError("pad_token_id must be set when eos_token_id is set")
            next_tokens = next_tokens * unfinished + pad_token_id * (1 - unfinished)

        input_ids = torch.cat([input_ids, next_tokens.unsqueeze(1)], dim=1)

        # update unfinished mask
        if eos_token_id is not None:
            eos_tensor = torch.tensor(eos_token_id, device=device)
            hit_eos = next_tokens.unsqueeze(1).eq(eos_tensor.unsqueeze(0)).any(dim=1)
            unfinished = unfinished * (~hit_eos).long()

        if unfinished.sum() == 0:
            break

        # stop if a complete function has been generated (prevents repetition)
        if stop_on_complete_function and tokenizer is not None:
            generated = input_ids[0, prompt_len:]
            if _is_complete_function(generated, tokenizer):
                break

        # stop if any of the stop_strings appears in the generated text
        if stop_strings and tokenizer is not None:
            generated = input_ids[0, prompt_len:]
            text = tokenizer.decode(generated, skip_special_tokens=True)
            hit = None
            for s in stop_strings:
                idx = text.find(s)
                if idx != -1:
                    hit = (s, idx)
                    break
            if hit is not None:
                s, idx = hit
                # Re-encode the prefix up to the stop string and replace generated tail
                prefix_text = text[:idx]
                prefix_ids = tokenizer(prefix_text, return_tensors="pt", add_special_tokens=False).input_ids[0].to(device)
                # Reconstruct: prompt + prefix_ids
                truncated = torch.cat([input_ids[0, :prompt_len], prefix_ids]).unsqueeze(0)
                # Pad to num_return_sequences shape (we only support N=1 path for stop_strings)
                input_ids = truncated.expand(num_return_sequences, -1).clone()
                break

    return input_ids
