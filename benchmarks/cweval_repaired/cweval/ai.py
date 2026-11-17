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


def _chat_message_text(message: object) -> str:
    """Preserve reasoning traces while keeping the final answer distinguishable."""
    content = getattr(message, 'content', None) or ''
    reasoning = (
        getattr(message, 'reasoning_content', None)
        or getattr(message, 'reasoning', None)
        or ''
    )
    model_extra = getattr(message, 'model_extra', None)
    if not reasoning and isinstance(model_extra, dict):
        reasoning = (
            model_extra.get('reasoning_content')
            or model_extra.get('reasoning')
            or ''
        )

    # A server without a reasoning parser may already return the complete
    # tagged response in content. Do not duplicate the trace in that case.
    if '</think>' in content or not reasoning:
        return content
    return f'<think>\n{reasoning}\n</think>\n\n{content}'


def _responses_text_with_summary(response: object) -> str:
    """Preserve returned summaries without mixing them into generated code."""
    summaries, answers = [], []
    for item in getattr(response, 'output', []) or []:
        if getattr(item, 'type', None) == 'reasoning':
            summaries.extend(
                block.text for block in getattr(item, 'summary', []) or []
                if getattr(block, 'type', None) == 'summary_text'
            )
        for block in getattr(item, 'content', []) or []:
            if getattr(block, 'type', None) == 'output_text':
                text = getattr(block.text, 'value', block.text)
                if isinstance(text, str):
                    answers.append(text)
    answer = ''.join(answers)
    if summaries:
        return '<think>\n[OpenAI reasoning summary]\n' + '\n\n'.join(summaries) + '\n</think>\n\n' + answer
    return answer


class AIAPI(abc.ABC):

    def __init__(
        self,
        model: str,
        **kwargs,
    ) -> None:
        self.model = model
        kwargs.pop('retry_empty', None)
        self.responses_model = model.removeprefix('openai/').startswith(('gpt-5', 'gpt-6'))
        self.reasoning_effort = kwargs.pop('reasoning_effort', None)
        self.reasoning_summary = kwargs.pop('reasoning_summary', 'detailed')
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
            ) or os.getenv(
                'OPENAI_BASE_URL'
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

        if self.backend in {'codex', 'claude'} or self.responses_model:
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
        if self.base_url or self.responses_model:
            request_kwargs = all_kwargs.copy()
            request_kwargs.pop('base_url', None)
            request_kwargs.pop('api_key', None)

            # GPT-5.x models are exposed through the Responses API.  Keep
            # this path direct so LiteLLM/chat-completions translation cannot
            # turn a model/API incompatibility into a worker-pool exception.
            if self.responses_model:
                if 'max_completion_tokens' in request_kwargs:
                    request_kwargs.setdefault(
                        'max_output_tokens', request_kwargs.pop('max_completion_tokens')
                    )
                request_kwargs.pop('max_tokens', None)
                n_samples = request_kwargs.pop('n', 1)
                request_kwargs.pop('seed', None)
                request_kwargs.pop('temperature', None)
                request_kwargs.pop('top_p', None)
                effort = self.reasoning_effort or 'medium'
                if self.model.removeprefix('openai/') == 'gpt-6.1-sol' and effort in {'none', 'minimal'}:
                    raise ValueError('gpt-6.1-sol requires reasoning effort low, medium, high, xhigh, or max')
                reasoning = {'effort': effort}
                if self.reasoning_summary != 'off':
                    reasoning['summary'] = self.reasoning_summary
                request_kwargs.setdefault('reasoning', reasoning)

                client = OpenAI(
                    api_key=self.api_key or 'EMPTY',
                    base_url=self.base_url or 'https://us.api.openai.com/v1',
                    max_retries=2 if request_kwargs.get('service_tier') == 'flex' else 0,
                    **({'timeout': 900.0} if request_kwargs.get('service_tier') == 'flex' else {}),
                )
                return [
                    _responses_text_with_summary(client.responses.create(
                        model=self.model.removeprefix('openai/'),
                        input=messages,
                        **request_kwargs,
                    ))
                    for _ in range(n_samples)
                ]

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
            return [_chat_message_text(c.message) for c in comp.choices]

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
            resp_this = [_chat_message_text(c.message) for c in comp.choices]
            assert len(resp_this) == n_this, f'{resp_this = } != {n_this = }'
            resp.extend(resp_this)

        return resp
