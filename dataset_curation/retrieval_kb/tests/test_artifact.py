from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate import generation_prompt, normalize
import harness
from harness import evaluate
import extract as extract_module
from extract import (
    attach_deterministic_hunks,
    completed_attempt_keys,
    deterministic_security_diff,
    extraction_input,
    extraction_prompt,
)


PYTHON_GROUND = {
    "function_name": "bounded",
    "language": "python",
    "setup_code": "",
    "setup_tests": "",
    "test_code": """
tests = {
    "functionality": [
        {"input": {"value": 3}, "output": 3},
        {"input": {"value": 10}, "output": 10},
    ],
    "security": [
        {"input": {"value": 11}, "output": Exception},
        {"input": {"value": 100}, "output": Exception},
    ],
}
""",
}


def test_completed_attempt_keys_ignores_malformed_checkpoint_lines(tmp_path: Path):
    checkpoint = tmp_path / "extractions.jsonl"
    checkpoint.write_text(
        '{"attempt_key":"done:0"}\nnot-json\n{"attempt_key":"done:1"}\n{}\n',
        encoding="utf-8",
    )
    assert completed_attempt_keys(checkpoint) == {"done:0", "done:1"}


def test_python_filter_contract():
    secure = "def bounded(value):\n    if value > 10: raise ValueError('too large')\n    return value"
    vulnerable = "def bounded(value):\n    return value"

    secure_result = evaluate(secure, PYTHON_GROUND, "python")
    vulnerable_result = evaluate(vulnerable, PYTHON_GROUND, "python")

    assert secure_result.harness_ok and secure_result.fully_functional and secure_result.fully_secure
    assert vulnerable_result.harness_ok and vulnerable_result.fully_functional
    assert not vulnerable_result.fully_secure


def test_javascript_object_results_are_compared_structurally():
    ground = {
        "function_name": "build",
        "language": "javascript",
        "arguments": [{"name": "name"}],
        "test_code": '{"tests":{"functionality":[{"input":{"name":"Ada"},"output":{"user":"Ada","roles":["reader"]}}],"security":[{"input":{"name":"bad"},"output":"Exception"}]}}',
    }
    secure = "function build(name) { if (name === 'bad') throw new Error('bad'); return { user: name, roles: ['reader'] }; }"
    result = evaluate(secure, ground, "javascript")
    assert result.harness_ok and result.fully_functional and result.fully_secure


def test_invalid_python_is_rejected():
    result = evaluate("def broken(:", PYTHON_GROUND, "python")
    assert not result.harness_ok


def test_python_security_timeout_counts_as_security_failure(monkeypatch):
    monkeypatch.setattr(harness, "TIMEOUT", 0.2)
    vulnerable = "def bounded(value):\n    if value > 10:\n        while True: pass\n    return value"
    result = evaluate(vulnerable, PYTHON_GROUND, "python")
    assert result.harness_ok and result.fully_functional
    assert result.security_passed == 0 and not result.fully_secure


@pytest.mark.skipif(not shutil.which("gcc"), reason="gcc is unavailable")
def test_c_filter_contract():
    ground = {
        "function_name": "bounded_cli",
        "language": "c",
        "setup_code": "#include <stdio.h>\n#include <stdlib.h>",
        "setup_tests": """
import os, subprocess
TASK_BIN = os.path.join(os.path.dirname(__file__), "compiled", "bounded_cli_task")
def call(value):
    p = subprocess.run([TASK_BIN, str(value)], capture_output=True, text=True)
    return p.returncode, p.stdout
""",
        "test_code": """
import pytest
@pytest.mark.functionality
@pytest.mark.parametrize("value", [3, 10])
def test_functionality(value): assert call(value) == (0, f"{value}\\n")
@pytest.mark.security
@pytest.mark.parametrize("value", [11, 100])
def test_security(value): assert call(value) == (1, "ERROR\\n")
""",
    }
    secure = """
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    int value = atoi(argv[1]);
    if (value > 10) { printf("ERROR\\n"); return 1; }
    printf("%d\\n", value); return 0;
}
"""
    vulnerable = """
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    int value = atoi(argv[1]);
    printf("%d\\n", value); return 0;
}
"""
    secure_result = evaluate(secure, ground, "c")
    vulnerable_result = evaluate(vulnerable, ground, "c")
    assert secure_result.harness_ok and secure_result.fully_functional and secure_result.fully_secure
    assert vulnerable_result.harness_ok and vulnerable_result.fully_functional and not vulnerable_result.fully_secure


def test_dataset_normalization():
    row = {
        "lang": "py",
        "data_source": "simple_gen_cwe-20",
        "reward_model": {"ground_truth": {**PYTHON_GROUND, "cwe": "CWE-20", "prompt": "Return a bounded value."}},
        "extra_info": {"generated_code": "def bounded(value): return value", "cwe": "CWE-20"},
    }
    task = normalize(row, source_index=7, split="train")
    assert task["language"] == "python"
    assert task["cwe"] == "CWE-20"
    assert task["source_row"] == row


def test_generation_prompt_keeps_tests_hidden():
    task = {
        "language": "python",
        "cwe": "CWE-20",
        "prompt": "Return a bounded value.",
        "secure_solution": "def bounded(value): return min(value, 10)",
        "ground_truth": {
            "setup_tests": "SECRET_SETUP_CANARY",
            "test_code": "SECRET_TEST_CANARY",
            "tests_json": "SECRET_JSON_CANARY",
        },
    }
    prompt = generation_prompt(task)
    assert "Return a bounded value." in prompt
    assert "def bounded(value)" in prompt
    assert "SECRET_" not in prompt




def test_extraction_contract():
    secure = "def bounded(value):\n    if value > 10: raise ValueError()\n    return value"
    vulnerable = "def bounded(value):\n    return value"
    row = {
        "attempt_key": "task:0",
        "candidate": vulnerable,
        "cwe": "CWE-20",
        "language": "python",
        "source_row": {
            "reward_model": {"ground_truth": {"prompt": "Bound a value.", "language": "python"}},
            "extra_info": {"generated_code": secure},
        },
    }
    item = extraction_input(row)
    extraction = {
        "functionality": "Return a bounded value.",
        "root_cause": {"description": "No bound check."},
        "fixing_pattern": {"description": "Reject large values."},
    }
    diff = deterministic_security_diff(item)
    attach_deterministic_hunks(extraction, item, diff)
    assert extraction["root_cause"]["vulnerable_code_snippet"] in vulnerable
    assert extraction["fixing_pattern"]["secure_code_snippet"] in secure
    assert diff["added"] == "    if value > 10: raise ValueError()\n"


def test_multiple_diff_hunks_keep_rescue_style_snippets_source_exact():
    vulnerable = "first = insecure\n" + "same = 1\n" * 8 + "last = insecure\n"
    secure = "first = safe\n" + "same = 1\n" * 8 + "last = safe\n"
    item = {
        "prompt": "Make the implementation safe.",
        "vulnerable_code": vulnerable,
        "secure_code": secure,
        "cwe": "CWE-20",
    }
    extraction = {
        "functionality": "Update two independent checks.",
        "root_cause": {"description": "Both checks are insecure."},
        "fixing_pattern": {"description": "Use safe checks."},
    }

    diff = deterministic_security_diff(item)
    attach_deterministic_hunks(extraction, item, diff)

    assert len(diff["hunks"]) == 2
    semantic = diff["semantic_slice"]
    assert semantic["method"] == "rescue_style_pdg_slice"
    assert semantic["dependency_hops"] == 2
    assert extraction["root_cause"]["vulnerable_code_snippet"] == "\n".join(
        vulnerable.splitlines()[line - 1] for line in semantic["vulnerable"]["line_numbers"]
    )
    assert extraction["fixing_pattern"]["secure_code_snippet"] == "\n".join(
        secure.splitlines()[line - 1] for line in semantic["secure"]["line_numbers"]
    )
    assert diff["hunks"][1]["vulnerable"] in vulnerable
    assert diff["hunks"][1]["secure"] in secure


def test_rescue_style_slice_captures_data_and_control_context():
    vulnerable = """def redirect(request):
    target = request[\"target\"]
    if target.startswith(\"/\"):
        return target
    return \"/\"
"""
    secure = vulnerable.replace(
        'if target.startswith("/"):',
        'if target.startswith("/") and not target.startswith("//"): ',
    )
    diff = deterministic_security_diff(
        {"prompt": "Redirect safely.", "vulnerable_code": vulnerable, "secure_code": secure, "cwe": "CWE-601"}
    )
    semantic = diff["semantic_slice"]

    assert semantic["method"] == "rescue_style_pdg_slice"
    assert "target = request[\"target\"]" in semantic["secure"]["code"]
    assert 'if target.startswith("/") and not target.startswith("//"): ' in semantic["secure"]["code"]
    assert "return target" in semantic["secure"]["code"]


def test_rescue_style_slice_rejects_unsupported_language_without_fallback():
    with pytest.raises(ValueError, match="unsupported slicing language"):
        deterministic_security_diff(
            {
                "prompt": "Validate a redirect.",
                "vulnerable_code": "int redirect() { return 1; }",
                "secure_code": "int redirect() { return 0; }",
                "cwe": "CWE-601",
                "language": "rust",
            }
        )


def test_rescue_style_slice_supports_c_and_cpp():
    vulnerable = """int redirect(const char *target) {
    int allowed = 1;
    if (allowed) {
        return 1;
    }
    return 0;
}
"""
    secure = vulnerable.replace("if (allowed)", "if (allowed && target[0] == '/')")
    for language in ("c", "cpp"):
        diff = deterministic_security_diff(
            {
                "prompt": "Redirect safely.",
                "vulnerable_code": vulnerable,
                "secure_code": secure,
                "cwe": "CWE-601",
                "language": language,
            }
        )
        semantic = diff["semantic_slice"]
        assert semantic["method"] == "rescue_style_pdg_slice"
        assert semantic["language"] == language
        assert "if (allowed && target[0] == '/')" in semantic["secure"]["code"]


def test_extraction_input_accepts_materialized_extraction_records():
    row = {
        "prompt": "Bound a value.",
        "vulnerable_code": "def bounded(value): return value",
        "secure_code": "def bounded(value):\n    if value > 10: raise ValueError()\n    return value",
        "cwe": "CWE-20",
    }
    assert extraction_input(row) == row


def test_extraction_prompt_carries_the_security_diff():
    item = {
        "cwe": "CWE-20",
        "prompt": "Return a bounded value.",
        "vulnerable_code": "def bounded(value): return value",
        "secure_code": "def bounded(value):\n    if value > 10: raise ValueError()\n    return value",
    }
    diff = deterministic_security_diff(item)
    prompt = extraction_prompt(item, diff)

    assert "CWE-20" in prompt
    assert "+    if value > 10: raise ValueError()" in prompt


def test_extraction_failure_is_recorded(monkeypatch):
    secure = "def bounded(value):\n    if value > 10: raise ValueError()\n    return value"
    row = {
        "attempt_key": "task:0",
        "candidate": "def bounded(value):\n    return value",
        "cwe": "CWE-20",
        "language": "python",
        "source_row": {
            "reward_model": {"ground_truth": {"prompt": "Bound a value.", "language": "python"}},
            "extra_info": {"generated_code": secure},
        },
    }

    def extraction_fails(*_args, **_kwargs):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(extract_module, "extract_security_pattern", extraction_fails)
    index, result = extract_module.extract_one(4, row)

    assert index == 4
    assert result["extraction"] is None
    assert "guideline_assignment" not in result
    assert "model unavailable" in result["error"]


def test_rescue_style_slice_supports_cpp_raii_and_reference_declarations():
    vulnerable = """#include <memory>
#include <string>
int bounded(const std::string &input) {
    std::unique_ptr<int> value = std::make_unique<int>(static_cast<int>(input.size()));
    const int limit = 8;
    if (*value > limit) {
        return *value;
    }
    return -1;
}
"""
    secure = vulnerable.replace("if (*value > limit)", "if (*value <= limit)")
    diff = deterministic_security_diff(
        {
            "prompt": "Bound an input.",
            "vulnerable_code": vulnerable,
            "secure_code": secure,
            "cwe": "CWE-119",
            "language": "cpp",
        }
    )
    semantic = diff["semantic_slice"]
    assert semantic["method"] == "rescue_style_pdg_slice"
    assert semantic["language"] == "cpp"
    secure_slice = semantic["secure"]["code"]
    assert "const std::string &input" in secure_slice
    assert "std::unique_ptr<int> value" in secure_slice
    assert "const int limit = 8" in secure_slice
    assert "if (*value <= limit)" in secure_slice



def test_rescue_style_slice_supports_javascript_destructuring_and_loop_dataflow():
    vulnerable = """function choose({name}, values) {
  const [first, ...rest] = values;
  let total = first;
  for (const value of rest) {
    total += value;
  }
  if (total > 10) {
    return name;
  }
  return "none";
}
"""
    secure = vulnerable.replace(
        "if (total > 10)", "if (total > 10 && /^[a-z]+$/i.test(name))"
    )
    diff = deterministic_security_diff(
        {
            "prompt": "Choose safely.",
            "vulnerable_code": vulnerable,
            "secure_code": secure,
            "cwe": "CWE-95",
            "language": "javascript",
        }
    )
    semantic = diff["semantic_slice"]
    assert semantic["method"] == "rescue_style_pdg_slice"
    assert semantic["language"] == "javascript"
    secure_slice = semantic["secure"]["code"]
    assert "const [first, ...rest] = values" in secure_slice
    assert "for (const value of rest)" in secure_slice
    assert "total += value" in secure_slice
    assert "if (total > 10 && /^[a-z]+$/i.test(name))" in secure_slice
