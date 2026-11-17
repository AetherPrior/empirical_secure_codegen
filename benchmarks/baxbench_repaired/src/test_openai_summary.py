import logging
from pathlib import Path
from types import SimpleNamespace

from openai import NOT_GIVEN
from prompts import Parser, Prompter


def test_qwen36_vllm_output_room_after_thinking(monkeypatch):
    calls = []
    def post(url, **kwargs):
        calls.append(kwargs['json'])
        return SimpleNamespace(raise_for_status=lambda: None,
            json=lambda: {'choices': [{'message': {'content': '<think>reason</think>\n```python\nsafe()\n```'}}]})
    monkeypatch.setattr('prompts.requests.post', post)
    prompter = Prompter.__new__(Prompter)
    prompter.__dict__.update(model='Qwen/Qwen3.6-27B', openai=False,
        completions=False, no_system_prompt=False, system_prompt='write code', prompt='task',
        reasoning_effort=None, max_thinking_tokens=8192, temperature=0.6,
        sample_seeds=[42], batch_size=1)
    prompter.prompt_vllm(logging.getLogger(__name__))
    assert Prompter.openai_together_context_lengths[prompter.model] == 40960
    assert calls[0]['max_tokens'] == 32768
    assert calls[0]['thinking_token_budget'] == 8192


def test_gpt6_request_and_summary_code_boundary(monkeypatch):
    calls = []
    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(output=[
            SimpleNamespace(type='reasoning', summary=[SimpleNamespace(type='summary_text', text='```python\ninsecure()\n```')]),
            SimpleNamespace(type='message', content=[SimpleNamespace(type='output_text', text='```python\nsafe()\n```')]),
        ])
    monkeypatch.setenv('OPENAI_API_KEY', 'test')
    monkeypatch.setattr('prompts.OpenAI', lambda **kwargs: SimpleNamespace(responses=SimpleNamespace(create=create)))
    prompter = Prompter.__new__(Prompter)
    prompter.__dict__.update(model='gpt-6.1-sol', openai=True, local=False, completions=False,
                            no_system_prompt=False, system_prompt='write code', prompt='task',
                            reasoning_effort='high', reasoning_summary='detailed', batch_size=3,
                            service_tier='flex',
                            temperature=0.6, o1_o3=False)
    outputs = prompter.prompt_openai_together_batch(logging.getLogger(__name__))
    assert len(outputs) == len(calls) == 3
    parser = Parser(SimpleNamespace(code_filename='app.py', is_multi_file=False), logging.getLogger(__name__))
    for output in outputs:
        assert '[OpenAI reasoning summary]' in output
        assert parser.parse_response(output) == {Path('app.py'): 'safe()'}
    for call in calls:
        assert call['model'] == 'gpt-6.1-sol'
        assert call['reasoning'] == {'effort': 'high', 'summary': 'detailed'}
        assert call['temperature'] is NOT_GIVEN
        assert call['max_output_tokens'] == 128000
        assert call['service_tier'] == 'flex'
        assert call['timeout'] == 900.0
