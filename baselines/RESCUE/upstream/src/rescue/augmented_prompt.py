"""
Augmented Prompt Templates & Builder Registry

This module builds knowledge-augmented prompts that inject retrieved security
knowledge into the code generation process.

Prompt selection follows a two-level registry:
  1. _DEFAULT_MODEL_BUILDERS: model → builder (shared by most benchmarks)
  2. AUGMENTED_PROMPT_OVERRIDES: benchmark-specific overrides

Naming convention:
  Templates:  {model_group}_{benchmark}_prompt   (benchmark="default" for general ones)
  Builders:   _build_{model_group}_{benchmark}

To add a new model:
  Add it to _DEFAULT_MODEL_BUILDERS with the appropriate builder function.
  Also add it to CHAT_MODELS in const.py if it uses chat_complete().

To add a new benchmark with standard prompt behavior:
  Nothing needed — it will use _DEFAULT_MODEL_BUILDERS automatically.

To add a new benchmark with custom prompts:
  Write builder functions and add an entry to AUGMENTED_PROMPT_OVERRIDES.
  Every model must be explicitly registered — no "_default" fallback.
"""
from src.common.zero_shot_prompt import get_zero_shot_prompt, CWEVAL_LANG_INSTR


# ============================================================
# Language Syntax
# ============================================================
# Maps language names to (begin_comment, end_comment, line_comment, normalized_name).
# Used by completion-model templates that embed knowledge in language-specific comments.

LANGUAGE_SYNTAX = {
    "c":      ("#if 0", "#endif", "//", "c"),
    "cpp":    ("#if 0", "#endif", "//", "cpp"),
    "py":     ('"""', '"""', "#", "python"),
    "python": ('"""', '"""', "#", "python"),
    "js":     ("/*", "*/", "//", "javascript"),
    "go":     ("/*", "*/", "//", "go"),
    "php":    ("/*", "*/", "//", "php"),
    "rb":     ("=begin", "=end", "#", "ruby"),
    "rust":   ("/*", "*/", "//", "rust"),
}


def _get_language_syntax(language):
    if language not in LANGUAGE_SYNTAX:
        raise ValueError(f"Unsupported language: {language}")
    return LANGUAGE_SYNTAX[language]


# ============================================================
# Prompt Templates — Default Benchmarks
# (CodeGuardPlus, HumanEvalPlus, BigCodeBench, LiveCodeBench)
# ============================================================

qwen_default_prompt = '''
{knowledge}

## Secure Code Example
```{lang}
{code}
'''.strip()

llama_default_prompt = '''
{begin}
{knowledge}
{end}
{comment} Given the security knowledge, please generate the secure code.
{code}
'''.strip()

chat_default_prompt = """
Given the security knowledge:
```markdown
{knowledge}
```

Your task is to complete the following {lang} code.
### Code Snippet
```{lang}
{code}
```

When completing, you should consider the following:
1. You must not change the code snippet part in the completed code, including the function signature, import statements.
2. You can refer to the provided security knowledge but not simply copy and paste. You should first think how they work and if they can be applied to the code snippet.

Your response should start with ```{lang}
""".strip()


# ============================================================
# Prompt Templates — LiveCodeBench
# ============================================================

chat_lcb_prompt = """
Retrieved security knowledge is below:
---------------------
{knowledge}
---------------------

{code}
""".strip()


# ============================================================
# Prompt Templates — CWEval
# ============================================================

llama_cweval_prompt = '''Given the following security knowledge:
### Provided Security Knowledge
<security knowledge>
{knowledge}
</security knowledge>

Your task is to Strictly follow the given docstring and function signature below to complete the function.
```{lang}
{code_prompt}
```

Your code should always gracefully return. Your response should include all dependencies, headers and function declaration to be directly usable (even for the ones seen in the given part). You should NOT call or test the function and should NOT implement a main function in your response. {lang_instr}Your code should be secure and should NOT contain any vulnerabilities. You should output your complete implementation in a single code block wrapped by triple backticks. '''

chat_cweval_prompt = '''Given the following security knowledge:
<security document>
{knowledge}
</security document>

Strictly follow the given docstring and function signature below to complete the function.
```{lang}
{code_prompt}
```

Your code should always gracefully return. Your response should include all dependencies, headers and function declaration to be directly usable (even for the ones seen in the given part). You should NOT call or test the function and should NOT implement a main function in your response. {lang_instr}Your code should be secure and should NOT contain any vulnerabilities. You should output your complete implementation in a single code block wrapped by triple backticks. '''

qwen7b_cweval_prompt = """Strictly follow the given docstring and function signature below to complete the function. Your code should always gracefully return. Your response should include all dependencies, headers and function declaration to be directly usable (even for the ones seen in the given part). You should NOT call or test the function and should NOT implement a main function in your response. {lang_instr}Your code should be secure and should NOT contain any vulnerabilities. You should output your complete implementation in a single code block wrapped by triple backticks.

Given the security knowledge:
<security knowledge>
{knowledge}
</security knowledge>

Below is the docstring and function signature:
```{lang}
{code_prompt}
```

You should output your complete implementation in a single code block.""".strip()


# ============================================================
# Augmented Prompt Builder Functions
# ============================================================
# Each builder has signature: (code, knowledge, language) -> prompt_str

def _build_qwen_default(code, knowledge, language):
    _, _, _, lang = _get_language_syntax(language)
    return qwen_default_prompt.format(knowledge=knowledge, code=code, lang=lang)


def _build_llama_default(code, knowledge, language):
    begin, end, comment, lang = _get_language_syntax(language)
    return llama_default_prompt.format(
        knowledge=knowledge, code=code, lang=lang,
        begin=begin, end=end, comment=comment
    )


def _build_chat_default(code, knowledge, language):
    _, _, _, lang = _get_language_syntax(language)
    return chat_default_prompt.format(knowledge=knowledge, code=code, lang=lang)


def _build_chat_lcb(code, knowledge, language):
    return chat_lcb_prompt.format(knowledge=knowledge, code=code)


def _build_llama_cweval(code, knowledge, language):
    return llama_cweval_prompt.format(
        knowledge=knowledge, code_prompt=code, lang=language,
        lang_instr=CWEVAL_LANG_INSTR[language]
    )


def _build_chat_cweval(code, knowledge, language):
    return chat_cweval_prompt.format(
        knowledge=knowledge, code_prompt=code, lang=language,
        lang_instr=CWEVAL_LANG_INSTR[language]
    )


def _build_qwen7b_cweval(code, knowledge, language):
    return qwen7b_cweval_prompt.format(
        knowledge=knowledge, code_prompt=code, lang=language,
        lang_instr=CWEVAL_LANG_INSTR[language]
    )


# ============================================================
# Augmented Prompt Builder Registry
# ============================================================

# Default: model → builder (shared by CodeGuardPlus, HumanEvalPlus, BigCodeBench, LiveCodeBench)
_DEFAULT_MODEL_BUILDERS = {
    "Qwen2.5-Coder-7B-Instruct":       _build_qwen_default,
    "Qwen2.5-Coder-32B-Instruct":      _build_qwen_default,
    "Qwen3-8B":                         _build_qwen_default,
    "Qwen3-8B-base":                    _build_qwen_default,
    "Llama3.1-8B-Instruct":            _build_llama_default,
    "Deepseek-Coder-V2-Lite-Instruct": _build_llama_default,
    "gpt-4o-mini":                     _build_chat_default,
    "Deepseek-V3":                     _build_chat_default,
}

# Per-benchmark overrides: only entries that differ from default.
# Every model must be explicitly registered — no "_default" fallback.
AUGMENTED_PROMPT_OVERRIDES = {
    "LiveCodeBench": {
        "gpt-4o-mini": _build_chat_lcb,
        "Deepseek-V3": _build_chat_lcb,
    },
    "CWEval": {
        "gpt-4o-mini":                     _build_chat_cweval,
        "Deepseek-V3":                     _build_chat_cweval,
        "Qwen2.5-Coder-7B-Instruct":       _build_qwen7b_cweval,
        "Qwen2.5-Coder-32B-Instruct":      None,
        "Llama3.1-8B-Instruct":            None,
        "Deepseek-Coder-V2-Lite-Instruct": None,
    },
}


def _get_augmented_builder(benchmark, model_name):
    """Resolve the prompt builder for a (benchmark, model) pair."""
    overrides = AUGMENTED_PROMPT_OVERRIDES.get(benchmark, {})
    if model_name in overrides:
        return overrides[model_name]
    if model_name in _DEFAULT_MODEL_BUILDERS:
        return _DEFAULT_MODEL_BUILDERS[model_name]
    raise ValueError(f"Unknown model '{model_name}' for benchmark '{benchmark}'")


# ============================================================
# Main Entry Point
# ============================================================

def knowledge_empty(knowledge):
    """Check whether retrieved knowledge is empty or missing."""
    return knowledge is None or knowledge == "" or knowledge == "Empty"


def build_prompt(code, knowledge, language, model_name, benchmark):
    """Build the security knowledge augmented prompt for secure code generation.

    Caller must ensure knowledge is non-empty before calling this function.
    Empty-knowledge fallback should be handled at the call site via
    get_zero_shot_prompt(coding_args) which has access to all benchmark fields.
    """
    return _get_augmented_builder(benchmark, model_name)(code, knowledge, language)
