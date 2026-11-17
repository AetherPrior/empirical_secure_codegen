"""
This file implements how to load models and how to invoke LLMs.
"""

from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
from src.common import const
from peft import PeftModel
import torch
from openai import OpenAI
import os
from src.common import utils

class OpenAILLM():
    def __init__(self, model, base_url = None, **sampling_params) -> None:
        openai_key = utils.load_yaml(const.CONF_SECRET_PATH)["openai-key"]
        self.client = OpenAI(api_key=openai_key,
                             base_url=base_url)
        self.model_name = model
        # define the model
        gen_config = {
            "model": model, 
            "temperature": 0.1,
            "max_tokens": 1024,
        }
        # update the passing parameters
        gen_config.update(**sampling_params)
        self.sampling_params = gen_config
    
    def chat_complete(self, **kw_args):
        system_prompt = kw_args.get("system_prompt")
        prompt = kw_args.get("prompt")
        n = 1 if kw_args.get("n") is None else kw_args.get("n")
        
        system_prompt = "You are a helpful assistant." if system_prompt is None else system_prompt
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
        response = self.client.chat.completions.create(
            messages = messages,
            n = n, 
            ** self.sampling_params
        )

        if n == 1:
            content =  response.choices[0].message.content
        else:
            content = [x.message.content for x in response.choices]
        return content, response


class VLLMLLM():
    def __init__(self, model, base_url, **sampling_params) -> None:
        super().__init__()
        openai_key = utils.load_yaml(const.CONF_SECRET_PATH)["vllm-key"] # get the api key from the environmental values.
        self.client = OpenAI(api_key=openai_key, base_url=base_url) # alter the base url for vllm 
        self.model_name = model
        # define the model
        gen_config = {
            "model": model, 
            "temperature": 0.1,
            "top_p": 1, 
            "max_tokens": 1024,
        }
        # update the passing parameters
        gen_config.update(**sampling_params)
        self.sampling_params = gen_config
    
    def chat_complete(self, **kw_args):
        system_prompt = kw_args.get("system_prompt")
        prompt = kw_args.get("prompt")
        n = 1 if kw_args.get("n") is None else kw_args.get("n")
        default_max_tokens = 8192 if self.model_name.startswith("Qwen3-") else 1024
        max_tokens = kw_args.get("max_tokens") if kw_args.get("max_tokens") else default_max_tokens
        self.sampling_params["max_tokens"] = max_tokens

        system_prompt = "You are a helpful assistant." if system_prompt is None else system_prompt
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
        response = self.client.chat.completions.create(
            messages = messages,
            n = n, 
            ** self.sampling_params
        )

        if n == 1:
            content =  response.choices[0].message.content
        else:
            content = [x.message.content for x in response.choices]
        return content, response

    def completion(self, **kw_args):
        prompt = kw_args.get("prompt")
        n = 1 if kw_args.get("n") is None else kw_args.get("n")
        max_tokens = kw_args.get("max_tokens") if kw_args.get("max_tokens") else 256
        self.sampling_params["max_tokens"] = max_tokens
        response = self.client.completions.create(
            prompt=prompt,
            n = n, 
            ** self.sampling_params
        )
        if n == 1:
            content =  response.choices[0].text
        else:
            content = [x.text for x in response.choices]
        return content, response


class DeepSeekLLM():
    def __init__(self, model, base_url, **sampling_params) -> None:
        openai_key = utils.load_yaml(const.CONF_SECRET_PATH)["deepseek-key"]
        self.client = OpenAI(api_key=openai_key, base_url=base_url)
        self.model_name = model
        # define the model
        gen_config = {
            "model": model, 
            "temperature": 0.1,
            "top_p": 1, 
            "max_tokens": 1024,
        }
        # update the passing parameters
        gen_config.update(**sampling_params)
        self.sampling_params = gen_config
    
    def chat_complete(self, **kw_args):
        system_prompt = kw_args.get("system_prompt")
        prompt = kw_args.get("prompt")
        n = 1 if kw_args.get("n") is None else kw_args.get("n")
        
        system_prompt = "You are a helpful assistant." if system_prompt is None else system_prompt
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
        response = self.client.chat.completions.create(
            messages = messages,
            n = n, 
            ** self.sampling_params
        )

        if n == 1:
            content =  response.choices[0].message.content
        else:
            content = [x.message.content for x in response.choices]
        return content, response


def load_model(model_name, **sampling_params):
    model_deploy_path = const.CONF_MODEL_DEPLOY_PATH
    config_dict = utils.load_yaml(model_deploy_path)
    if model_name not in config_dict:
        raise NotImplementedError(f'{model_name} cannot be used.')
    config = config_dict[model_name]

    if model_name in ["gpt-4o-mini", "gpt-4o"]:
        serve_model_name = config["serve-model-name"]
        base_url = config["base_url"]
        model = OpenAILLM(serve_model_name, base_url, **sampling_params)
    elif model_name in ["Llama3.1-8B-Instruct", "Qwen2.5-Coder-7B-Instruct",
                         "Deepseek-Coder-V2-Lite-Instruct",
                         "Qwen2.5-Coder-32B-Instruct", "Qwen3-8B", "Qwen3-8B-base"]:
        serve_model_name = config["serve-model-name"]
        host, port = config["host"], config["port"]
        base_url = f"http://{host}:{port}/v1"
        model = VLLMLLM(serve_model_name, base_url, **sampling_params)
    elif model_name in ["Deepseek-V3"]:
        serve_model_name = config["serve-model-name"]
        base_url = config["base_url"]
        model = DeepSeekLLM(serve_model_name, base_url, **sampling_params)
    return model


if __name__ == '__main__':
    pass
