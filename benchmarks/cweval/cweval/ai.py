import abc
import os
import sys
from pathlib import Path
from typing import Dict, List

import litellm
from openai import OpenAI

try:
    from agent_cli import run_agent
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent_cli import run_agent

# litellm.set_verbose = True


class AIAPI(abc.ABC):

    def __init__(
        self,
        model: str,
        **kwargs,
    ) -> None:
        self.model = model
        self.backend = kwargs.pop('backend', 'api')
        self.codex_reasoning_effort = kwargs.pop('codex_reasoning_effort', 'none')
        self.claude_effort = kwargs.pop('claude_effort', 'low')
        self.agent_max_budget_usd = kwargs.pop('agent_max_budget_usd', None)
        self.agent_timeout = kwargs.pop('agent_timeout', 600)
        self.base_url = kwargs.pop('base_url', None) or kwargs.pop('api_base', None)
        self.api_key = kwargs.pop('api_key', None)
        if not self.base_url:
            self.base_url = os.getenv('LITELLM_API_BASE') or os.getenv(
                'OPENAI_API_BASE'
            )
        if not self.api_key:
            self.api_key = os.getenv('LITELLM_API_KEY') or os.getenv('OPENAI_API_KEY')
        if self.base_url and not self.api_key:
            self.api_key = 'EMPTY'

        self.req_kwargs = kwargs
        if self.base_url is not None:
            self.req_kwargs.setdefault('base_url', self.base_url)
        if self.api_key is not None:
            self.req_kwargs.setdefault('api_key', self.api_key)

        if self.backend in {'codex', 'claude'}:
            # CLI-agent backends do not use LiteLLM's provider resolution.
            # In particular, arbitrary CLI model aliases such as
            # ``gpt-5.6-sol`` should not need an ``openai/`` prefix here.
            self.provider = None
        else:
            try:
                _, self.provider, _, _ = litellm.get_llm_provider(
                    self.model,
                    api_base=self.base_url,
                    api_key=self.api_key,
                )
            except litellm.exceptions.BadRequestError:
                if self.base_url and not self.model.startswith('openai/'):
                    self.model = f'openai/{self.model}'
                    _, self.provider, _, _ = litellm.get_llm_provider(
                        self.model,
                        api_base=self.base_url,
                        api_key=self.api_key,
                    )
                else:
                    raise

    def send_message(self, messages: List[Dict[str, str]], **kwargs) -> List[str]:
        all_kwargs = self.req_kwargs.copy()
        all_kwargs.update(kwargs)

        if self.backend in {'codex', 'claude'}:
            n_samples = all_kwargs.pop('n', 1)
            system_prompt = next(
                (m.get('content', '') for m in messages if m.get('role') == 'system'),
                '',
            )
            prompt = next(
                (m.get('content', '') for m in reversed(messages) if m.get('role') == 'user'),
                '',
            )
            return [
                run_agent(
                    prompt,
                    backend=self.backend,
                    model=self.model,
                    system_prompt=system_prompt,
                    api_base=self.base_url,
                    service_tier=all_kwargs.get('service_tier'),
                    codex_reasoning_effort=self.codex_reasoning_effort,
                    claude_effort=self.claude_effort,
                    max_budget_usd=self.agent_max_budget_usd,
                    timeout=self.agent_timeout,
                )
                for _ in range(n_samples)
            ]

        # The local gateways expose an OpenAI-compatible endpoint even when
        # the routed model name has an Anthropic or Gemini prefix.  Use the
        # OpenAI client for those endpoints so LiteLLM does not rewrite the
        # request to a provider-native /v1/messages URL.
        if self.base_url:
            request_kwargs = all_kwargs.copy()
            request_kwargs.pop('base_url', None)
            request_kwargs.pop('api_key', None)

            # GPT-5.x models are exposed through the Responses API.  Keep
            # this path direct so LiteLLM/chat-completions translation cannot
            # turn a model/API incompatibility into a worker-pool exception.
            if self.model.startswith('gpt-5') or self.model.startswith('openai/gpt-5'):
                if 'max_completion_tokens' in request_kwargs:
                    request_kwargs.setdefault(
                        'max_output_tokens', request_kwargs.pop('max_completion_tokens')
                    )
                request_kwargs.pop('max_tokens', None)
                request_kwargs.pop('n', None)
                request_kwargs.setdefault(
                    'reasoning', {'effort': 'medium', 'summary': 'detailed'}
                )

                client = OpenAI(
                    api_key=self.api_key or 'EMPTY',
                    base_url=self.base_url,
                    max_retries=0,
                )
                response = client.responses.create(
                    model=self.model.removeprefix('openai/'),
                    input=messages,
                    **request_kwargs,
                )
                chunks = []
                for item in getattr(response, 'output', []) or []:
                    for block in getattr(item, 'content', []) or []:
                        if getattr(block, 'type', None) == 'output_text':
                            value = getattr(block.text, 'value', None)
                            chunks.append(value if isinstance(value, str) else str(block.text))
                return [''.join(chunks)]

            if 'max_completion_tokens' in request_kwargs:
                request_kwargs.setdefault(
                    'max_tokens', request_kwargs.pop('max_completion_tokens')
                )
            if 'claude' in self.model.lower():
                request_kwargs.pop('temperature', None)

            client = OpenAI(
                api_key=self.api_key or 'EMPTY',
                base_url=self.base_url,
                max_retries=0,
            )
            n_samples = request_kwargs.pop('n', 1)
            if n_samples > 1:
                request_kwargs['n'] = n_samples
            comp = client.chat.completions.create(
                # ``openai/`` is a LiteLLM routing prefix, not part of the
                # model name exposed by an OpenAI-compatible local server.
                model=self.model.removeprefix('openai/'),
                messages=messages,
                **request_kwargs,
            )
            return [
                c.message.content
                if c.message.content is not None
                else (getattr(c.message, 'reasoning', None) or '')
                for c in comp.choices
            ]

        if self.provider == ['gemini', 'vertex_ai'] and 'gemini' in self.model:
            all_kwargs['safety_settings'] = [
                {
                    "category": "HARM_CATEGORY_HARASSMENT",
                    "threshold": "BLOCK_NONE",
                },
                {
                    "category": "HARM_CATEGORY_HATE_SPEECH",
                    "threshold": "BLOCK_NONE",
                },
                {
                    "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                    "threshold": "BLOCK_NONE",
                },
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_NONE",
                },
            ]

        n_samples = all_kwargs.pop('n', 1)
        max_n_per_req: int = {
            'openai': 128,
            'gemini': 8,
        }.get(self.provider, 1)

        resp: List[str] = []
        for i, idx in enumerate(range(0, n_samples, max_n_per_req)):
            n_this = min(max_n_per_req, n_samples - i * max_n_per_req)
            if n_this > 1:
                all_kwargs['n'] = n_this
            else:
                all_kwargs.pop('n', 1)

            comp = litellm.completion(
                model=self.model,
                messages=messages,
                num_retries=3,
                **all_kwargs,
            )
            # Some reasoning-enabled OpenAI-compatible servers return a null
            # content field when generation ends before a separate final
            # answer is emitted.  Preserve the response as text so one such
            # task does not abort the whole parallel generation sweep.
            resp_this = [
                c.message.content
                if c.message.content is not None
                else (getattr(c.message, 'reasoning', None) or '')
                for c in comp.choices
            ]
            assert len(resp_this) == n_this, f'{resp_this = } != {n_this = }'
            resp.extend(resp_this)

        return resp
