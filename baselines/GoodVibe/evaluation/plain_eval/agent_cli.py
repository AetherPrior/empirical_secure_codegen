"""Low-overhead one-turn adapters for installed coding-agent CLIs."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


def _json_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("result", "output_text", "text", "message"):
            if key in value:
                text = _json_text(value[key])
                if text:
                    return text
    if isinstance(value, list):
        for item in reversed(value):
            text = _json_text(item)
            if text:
                return text
    return ""


def run_agent(
    prompt: str,
    *,
    backend: str,
    model: str,
    system_prompt: str = "",
    api_base: Optional[str] = None,
    service_tier: Optional[str] = None,
    codex_reasoning_effort: str = "none",
    claude_effort: str = "low",
    max_budget_usd: Optional[float] = None,
    timeout: int = 600,
) -> str:
    """Run exactly one non-interactive CLI turn; never retries."""
    if backend == "codex":
        executable = shutil.which("codex")
        if not executable:
            raise RuntimeError("codex CLI is not installed or not on PATH")
        with tempfile.TemporaryDirectory(prefix="benchmark_codex_") as temp_dir:
            output_path = os.path.join(temp_dir, "last_message.txt")
            content = prompt
            if system_prompt:
                content = f"{system_prompt}\n\n{prompt}"
            command = [
                executable,
                "exec",
                "--color", "never",
                "--skip-git-repo-check",
                "--sandbox", "read-only",
                "--cd", temp_dir,
                "--ephemeral",
                "--ignore-user-config",
                "--disable", "shell_tool",
                "--disable", "browser_use",
                "--disable", "computer_use",
                "--disable", "apps",
                "--model", model,
                "--output-last-message", output_path,
                "-",
            ]
            if api_base:
                command[2:2] = ["-c", f"openai_base_url={json.dumps(api_base)}"]
            if service_tier:
                command[2:2] = ["-c", f"service_tier={json.dumps(service_tier)}"]
            if codex_reasoning_effort:
                command[2:2] = [
                    "-c",
                    f"model_reasoning_effort={json.dumps(codex_reasoning_effort)}",
                ]
            result = subprocess.run(
                command,
                input=content,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip())
            if os.path.exists(output_path):
                return Path(output_path).read_text(encoding="utf-8").strip()
            try:
                return _json_text(json.loads(result.stdout)).strip()
            except json.JSONDecodeError:
                return result.stdout.strip()

    if backend == "claude":
        executable = shutil.which("claude")
        if not executable:
            raise RuntimeError("Claude Code CLI is not installed or not on PATH")
        command = [
            executable,
            # safe-mode keeps OAuth/keychain login available; --bare does not.
            "--safe-mode",
            "--print",
            "--output-format", "json",
            "--no-session-persistence",
            "--permission-mode", "dontAsk",
            "--permission-prompts", "none",
            "--tools", "",
            "--system-prompt", system_prompt or "",
            "--effort", claude_effort,
        ]
        if max_budget_usd is not None:
            command += ["--max-budget-usd", str(max_budget_usd)]
        command += ["--model", model, prompt]
        result = subprocess.run(
            command, text=True, capture_output=True, timeout=timeout
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip())
        try:
            return _json_text(json.loads(result.stdout)).strip()
        except json.JSONDecodeError:
            return result.stdout.strip()

    raise ValueError(f"unknown agent backend: {backend}")
