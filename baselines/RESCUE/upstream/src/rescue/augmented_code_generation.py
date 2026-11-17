"""
RESCUE: Knowledge-Augmented Secure Code Generation

This module provides the run() entry point for the RESCUE method.
Prompt construction is handled by augmented_prompt.py.
"""
import time

from src.rescue.retrieval import hmr
from src.common.model import load_model
from src.common.zero_shot_prompt import get_zero_shot_prompt
from src.common.const import CHAT_MODELS
from src.rescue.augmented_prompt import build_prompt, knowledge_empty
from src.common import utils


def run(coding_args: dict):
    knowledge, cost_time_dict = hmr.hierarchical_multi_faceted_retrieve(coding_args)
    model_name = coding_args["model_name"]
    benchmark = coding_args["benchmark"]
    model = load_model(model_name, temperature=0.2)

    # For benchmark CWEval always uses chat API regardless of model type
    is_chat = model_name in CHAT_MODELS or benchmark == "CWEval"

    gen_time_start = time.perf_counter()

    if knowledge_empty(knowledge):
        # No knowledge retrieved, fall back to zero-shot prompt.
        # Use coding_args directly so all benchmark-specific fields are available.
        input_prompt = get_zero_shot_prompt(coding_args)
    else:
        # LiveCodeBench uses the zero-shot prompt as the code input
        if benchmark == "LiveCodeBench":
            code = get_zero_shot_prompt(coding_args)
        else:
            code = coding_args["code_snippet"]
        input_prompt = build_prompt(code, knowledge, coding_args["language"], model_name, benchmark)

    cost_time_dict["aug_token_input"] = utils.count_tokens(input_prompt)

    if is_chat:
        content, _ = model.chat_complete(prompt=input_prompt)
    else:
        content, _ = model.completion(prompt=input_prompt)

    cost_time_dict["aug_token_output"] = utils.count_tokens(content)

    gen_time = time.perf_counter() - gen_time_start
    return dict(
        input_prompt=input_prompt,
        final_prediction=content,
        gen_time=gen_time,
        **cost_time_dict,
    )
