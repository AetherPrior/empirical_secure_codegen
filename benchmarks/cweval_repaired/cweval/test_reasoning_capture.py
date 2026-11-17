from types import SimpleNamespace

from cweval.ai import AIAPI, _chat_message_text, _responses_text_with_summary
from cweval.commons import answer_after_thinking, get_code_from


def test_chat_message_text_merges_parser_fields() -> None:
    message = SimpleNamespace(
        reasoning_content='consider a risky implementation',
        reasoning=None,
        content='```python\nreturn safe_value\n```',
        model_extra=None,
    )

    saved = _chat_message_text(message)

    assert saved == (
        '<think>\nconsider a risky implementation\n</think>\n\n'
        '```python\nreturn safe_value\n```'
    )


def test_chat_message_text_preserves_embedded_reasoning() -> None:
    content = '<think>already embedded</think>\n```c\nreturn 0;\n```'
    message = SimpleNamespace(
        reasoning_content='already embedded',
        reasoning=None,
        content=content,
        model_extra=None,
    )

    assert _chat_message_text(message) == content


def test_no_reasoning_response_is_unchanged() -> None:
    content = '```cpp\nreturn value;\n```'
    message = SimpleNamespace(
        reasoning_content=None,
        reasoning=None,
        content=content,
        model_extra=None,
    )

    assert _chat_message_text(message) == content
    assert answer_after_thinking(content) == content


def test_code_extraction_ignores_fenced_code_in_reasoning() -> None:
    response = (
        '<think>\n```python\nreturn insecure_value\n```\n</think>\n\n'
        '```python\nreturn safe_value\n```'
    )

    final_answer = answer_after_thinking(response)

    assert get_code_from(final_answer, only_first=True) == 'return safe_value'


def test_responses_summary_and_no_summary() -> None:
    answer = SimpleNamespace(type='message', content=[SimpleNamespace(type='output_text', text='```python\nreturn safe_value\n```')])
    reasoning = SimpleNamespace(type='reasoning', summary=[SimpleNamespace(type='summary_text', text='```python\nreturn insecure_value\n```')])
    saved = _responses_text_with_summary(SimpleNamespace(output=[reasoning, answer]))
    assert '[OpenAI reasoning summary]' in saved
    assert get_code_from(answer_after_thinking(saved), only_first=True) == 'return safe_value'
    assert _responses_text_with_summary(SimpleNamespace(output=[answer])) == answer.content[0].text


def test_gpt6_responses_requests_preserve_three_samples(monkeypatch) -> None:
    calls = []
    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(output=[SimpleNamespace(type='message', content=[SimpleNamespace(type='output_text', text=str(len(calls)))])])
    monkeypatch.setattr('cweval.ai.OpenAI', lambda **kwargs: SimpleNamespace(responses=SimpleNamespace(create=create)))
    ai = AIAPI('gpt-6.1-sol', api_key='test', reasoning_effort='high', n=3,
               max_completion_tokens=8192, temperature=0.6, seed=42, service_tier='flex')
    assert ai.send_message([{'role': 'user', 'content': 'write code'}]) == ['1', '2', '3']
    assert len(calls) == 3
    for call in calls:
        assert call['reasoning'] == {'effort': 'high', 'summary': 'detailed'}
        assert call['max_output_tokens'] == 8192
        assert call['service_tier'] == 'flex'
        assert not {'seed', 'temperature', 'n', 'max_completion_tokens'} & call.keys()
