import torch
from typing import Optional, Tuple, Union, List
from transformers import GPTBigCodeForCausalLM, PhiForCausalLM, Cache, DynamicCache, Qwen3ForCausalLM
from transformers.modeling_outputs import CausalLMOutputWithCrossAttentions

class GPTBigCodeForPrefix(GPTBigCodeForCausalLM):
    def __init__(self, config):
        super().__init__(config)
        self.prefix_params = torch.nn.ParameterList()

        for _ in range(2):
            for _ in range(config.n_layer):
                param_size = (10, config.n_embd // config.n_head * 2)
                param = torch.nn.Parameter(torch.zeros(param_size, requires_grad=True))
                self.prefix_params.append(param)

        self.dropout = torch.nn.Dropout(0.1)

    def get_past_from_prefix(self, control_ids):
        past = list()
        for i in range(self.config.n_layer):
            stack = []
            for control_id in control_ids:
                idx = control_id * self.config.n_layer + i
                param = self.prefix_params[idx]
                stack.append(self.dropout(param))
            past.append(torch.stack(stack))
        return past

    def prepare_inputs_for_generation(self, input_ids, past_key_values=None, inputs_embeds=None, **kwargs):
        if past_key_values:
            if self.config.multi_query:
                past_length = past_key_values[0].shape[1]
            else:
                past_length = past_key_values[0].shape[2]

            if input_ids.shape[1] > past_length:
                remove_prefix_length = past_length
            else:
                remove_prefix_length = input_ids.shape[1] - 1

            input_ids = input_ids[:, remove_prefix_length:]

        else:
            control_ids = [0] * input_ids.shape[0]
            past_key_values = self.get_past_from_prefix(control_ids)

        return {
                "input_ids": input_ids,
                "past_key_values": past_key_values,
                "use_cache": kwargs.get("use_cache"),
                "position_ids": None,
                "attention_mask": None,
                "token_type_ids": None,
        }

class PhiPrefix(PhiForCausalLM):
    def __init__(self, config):
        super().__init__(config)

        embed_size_per_head = config.hidden_size // config.num_key_value_heads
        self.prefix_params = torch.nn.ParameterList()
        for _ in range(2):
            for _ in range(config.num_hidden_layers):
                for _ in range(2):
                    param_size = (config.num_key_value_heads, 10, embed_size_per_head)
                    param = torch.nn.Parameter(torch.zeros(param_size, requires_grad=True))
                    self.prefix_params.append(param)

        self.dropout = torch.nn.Dropout(0.1)

    def get_past_from_prefix(self, control_ids):
        past = list()
        for i in range(self.config.num_hidden_layers):
            past.append(list())
            key_stack, val_stack = [], []
            for control_id in control_ids:
                key_idx = control_id * self.config.num_hidden_layers * 2 + i * 2
                val_idx = key_idx + 1
                key = self.dropout(self.prefix_params[key_idx])
                val = self.dropout(self.prefix_params[val_idx])
                key_stack.append(key)
                val_stack.append(val)
            past[i].append(torch.stack(key_stack))
            past[i].append(torch.stack(val_stack))
        return past

    def prepare_inputs_for_generation(
        self, input_ids, past_key_values=None, attention_mask=None, inputs_embeds=None, **kwargs
    ):
        if past_key_values is not None:
            past_length = past_key_values[0][0].shape[2]

            if input_ids.shape[1] > past_length:
                remove_prefix_length = past_length
            else:
                remove_prefix_length = input_ids.shape[1] - 1

            input_ids = input_ids[:, remove_prefix_length:]
        else:
            control_ids = [0] * input_ids.shape[0]
            past_key_values = self.get_past_from_prefix(control_ids)

        return {
                "input_ids": input_ids,
                "position_ids": None,
                "past_key_values": past_key_values,
                "use_cache": kwargs.get("use_cache"),
                "attention_mask": None,
        }


class Qwen3Prefix(Qwen3ForCausalLM):
    """SVEN prefix-tuning for Qwen3: 2 controls (secure, vulnerable) x layers x (key, value), each (kv_heads, 10, head_dim).
    The prefix is injected as a pre-filled KV cache, as in SVEN's StarCoder/Phi models."""
    def __init__(self, config):
        super().__init__(config)
        hd = getattr(config, 'head_dim', None) or config.hidden_size // config.num_attention_heads
        self.prefix_params = torch.nn.ParameterList()
        for _ in range(2):
            for _ in range(config.num_hidden_layers):
                for _ in range(2):
                    self.prefix_params.append(torch.nn.Parameter(torch.zeros((config.num_key_value_heads, 10, hd), dtype=torch.float32)))
        self.prefix_dropout = torch.nn.Dropout(0.1)

    def get_past_from_prefix(self, control_ids):
        L = self.config.num_hidden_layers
        cache = DynamicCache()
        dt = self.dtype
        for i in range(L):
            ks, vs = [], []
            for c in control_ids:
                c = int(c)
                k = self.prefix_dropout(self.prefix_params[c * L * 2 + i * 2])
                v = self.prefix_dropout(self.prefix_params[c * L * 2 + i * 2 + 1])
                ks.append(k); vs.append(v)
            cache.update(torch.stack(ks).to(dt), torch.stack(vs).to(dt), i)
        return cache
