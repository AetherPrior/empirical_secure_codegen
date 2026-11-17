from src.common.utils import trans_pl_name
from src.common.model import load_model
from typing import Dict
from src.common import zero_shot_prompt
from src.common import utils
from src.common.const import CHAT_MODELS


def run(coding_args: Dict):
    prompt = zero_shot_prompt.get_zero_shot_prompt(coding_args)
    model_name = coding_args["model_name"]
    model = load_model(model_name, temperature = 0.2)
    if coding_args["benchmark"] == "CWEval" or model_name in CHAT_MODELS:
        print(f'[Debug] ----- Prompt -----\n{prompt}')
        if coding_args["benchmark"] == "LiveCodeBench":
            system_prompt = zero_shot_prompt.PromptConstants.SYSTEM_MESSAGE_GENERIC
        else:
            system_prompt = None
        input_tokens = utils.count_tokens(prompt)
        content, _ = model.chat_complete(prompt = prompt, system_prompt = system_prompt)
    else:
        input_tokens = utils.count_tokens(prompt)
        content, _ = model.completion(prompt = prompt)
    output_tokens = utils.count_tokens(content)
    return dict(input = prompt,final_prediction = content, input_tokens = input_tokens, output_tokens = output_tokens)

if __name__ == "__main__":
    pass
