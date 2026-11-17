#!/usr/bin/env python3
"""Generate functional-but-vulnerable programs from anonymous/RL_seccode_gen."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

from harness import Evaluation, evaluate


DEFAULT_DATASET = "anonymous/RL_seccode_gen"
MODEL = "gpt-5.4-mini"
SERVICE_TIER = os.getenv("OPENAI_SERVICE_TIER", "flex")
PROMPT_VERSION = "blind-v1"
SYSTEM_PROMPT = """You create negative examples for a controlled code-security benchmark.
Return only one complete source file, with no Markdown or explanation. The program must:
1. preserve the requested behavior and public interface;
2. remain syntactically valid and executable;
3. contain the requested CWE through one localized, plausible developer mistake.
Write code that could realistically occur when a developer misunderstands or omits a
security requirement. Do not target particular inputs, payloads, URLs, users, or roles.
Do not add input-specific branches, constant returns, artificial exceptions, no-op checks,
test or harness inspection, or comments revealing that the weakness is intentional.
The weakness must arise naturally from the implementation itself."""

_FENCE = re.compile(r"```(?:[\w+.-]+)?\s*\n?(.*?)```", re.DOTALL)
_CLIENTS = threading.local()


def jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    if hasattr(value, "as_py"):
        return jsonable(value.as_py())
    return str(value)


def load_rows(source: str, split: str) -> list[dict[str, Any]]:
    """Load Hugging Face, Parquet, JSONL, or JSON input."""
    path = Path(source)
    if path.exists():
        if path.suffix == ".parquet":
            import pyarrow.parquet as pq

            return [jsonable(row) for row in pq.read_table(path).to_pylist()]
        if path.suffix == ".jsonl":
            with path.open(encoding="utf-8") as handle:
                return [json.loads(line) for line in handle if line.strip()]
        if path.suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                raise ValueError("JSON input must contain a list of records")
            return [jsonable(row) for row in data]
        raise ValueError(f"unsupported input format: {path.suffix}")

    from datasets import load_dataset

    dataset = load_dataset(source, split=split)
    return [jsonable(row) for row in dataset]


def normalize(row: dict[str, Any], source_index: int, split: str) -> dict[str, Any]:
    reward_model = row.get("reward_model")
    ground_truth = reward_model.get("ground_truth") if isinstance(reward_model, dict) else None
    extra = row.get("extra_info")
    if not isinstance(ground_truth, dict) or not isinstance(extra, dict):
        raise ValueError("missing reward_model.ground_truth or extra_info")

    language = ground_truth.get("language") or row.get("lang") or extra.get("language") or extra.get("lang")
    aliases = {"py": "python", "python3": "python", "js": "javascript", "node": "javascript", "c++": "cpp"}
    language = aliases.get(str(language).lower(), str(language).lower())
    language_field = {"c": "candidate_c", "cpp": "candidate_cpp", "javascript": "candidate_js"}.get(language)
    secure_solution = extra.get(language_field) if language_field else None
    secure_solution = secure_solution or extra.get("generated_code")
    if not isinstance(secure_solution, str) or not secure_solution.strip():
        raise ValueError("missing secure reference solution")

    prompt = ground_truth.get("prompt") or extra.get("user_prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        messages = row.get("prompt") if isinstance(row.get("prompt"), list) else []
        prompt = "\n\n".join(
            message.get("content", "")
            for message in messages
            if isinstance(message, dict) and message.get("role") == "user"
        )
    cwe = ground_truth.get("cwe") or extra.get("cwe") or row.get("data_source")
    identity = json.dumps(
        [split, source_index, language, cwe, ground_truth.get("function_name"), prompt],
        ensure_ascii=False,
        sort_keys=True,
    )
    return {
        "id": hashlib.sha256(identity.encode("utf-8", errors="surrogatepass")).hexdigest()[:20],
        "source_index": source_index,
        "language": language,
        "cwe": str(cwe),
        "prompt": prompt,
        "secure_solution": secure_solution,
        "ground_truth": ground_truth,
        "source_row": row,
    }


def generation_prompt(task: dict[str, Any]) -> str:
    return f"""Language: {task['language']}
CWE pattern to model: {task['cwe']}

Task:
{task['prompt']}

Known-secure reference implementation:
```{task['language']}
{task['secure_solution']}
```

Rewrite the reference as a normal-looking implementation in which a developer makes
one common, localized mistake corresponding to {task['cwe']}. Preserve the task's
functionality and interface. Return code only."""


def extract_code(response: str) -> str:
    matches = _FENCE.findall(response or "")
    return (matches[-1] if matches else response or "").strip()


def client_for_thread():
    client = getattr(_CLIENTS, "client", None)
    if client is None:
        from openai import OpenAI

        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise RuntimeError("OPENAI_API_KEY is not set")
        client = OpenAI(api_key=key, base_url=os.getenv("OPENAI_BASE_URL") or None)
        _CLIENTS.client = client
    return client


def generate_one(task: dict[str, Any], attempt: int, args: argparse.Namespace) -> dict[str, Any]:
    key = f"{task['id']}:{attempt}"
    try:
        request: dict[str, Any] = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": generation_prompt(task)},
            ],
            "temperature": args.temperature,
            "max_completion_tokens": args.max_tokens,
            "service_tier": SERVICE_TIER,
        }
        if args.seed is not None:
            request["seed"] = args.seed + task["source_index"] * args.attempts + attempt
        response = client_for_thread().chat.completions.create(**request)
        raw = response.choices[0].message.content or ""
        usage = (
            response.usage.model_dump()
            if response.usage is not None and hasattr(response.usage, "model_dump")
            else jsonable(response.usage)
        )
        return {
            "attempt_key": key,
            "attempt": attempt,
            "candidate": extract_code(raw),
            "generation_error": "",
            "provider_model": response.model,
            "finish_reason": response.choices[0].finish_reason,
            "usage": usage,
        }
    except Exception as exc:
        return {
            "attempt_key": key,
            "attempt": attempt,
            "candidate": "",
            "generation_error": f"{type(exc).__name__}: {exc}",
        }


def evaluate_one(task: dict[str, Any], generated: dict[str, Any]) -> dict[str, Any]:
    result = safe_evaluate(generated["candidate"], task)
    accepted = (
        result.harness_ok
        and result.fully_functional
        and result.security_total > 0
        and 0 <= result.security_passed < result.security_total
    )
    return {
        **generated,
        "evaluation": result.to_dict(),
        "accepted": accepted,
        "rejection_reason": rejection_reason(result) if not accepted else "",
    }


def safe_evaluate(candidate: str, task: dict[str, Any]) -> Evaluation:
    try:
        return evaluate(candidate, task["ground_truth"], task["language"])
    except Exception as exc:
        return Evaluation(False, error=f"{type(exc).__name__}: {exc}")


def rejection_reason(result: Evaluation) -> str:
    if not result.harness_ok:
        return "invalid_or_harness_error"
    if result.functionality_total <= 0:
        return "no_functionality_tests"
    if not result.fully_functional:
        return "functionality_failed"
    if result.security_total <= 0:
        return "no_security_tests"
    return "all_security_tests_passed"


def parallel_map(function, items: list[Any], workers: int) -> list[Any]:
    if not items:
        return []
    results: list[Any] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(function, item) for item in items]
        for future in as_completed(futures):
            results.append(future.result())
    return results


def read_seen(path: Path) -> set[str]:
    if not path.exists():
        return set()
    seen: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = value.get("attempt_key")
            if isinstance(key, str):
                seen.add(key)
    return seen


def append_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(jsonable(row), ensure_ascii=False) + "\n")
        handle.flush()


def output_record(task: dict[str, Any], result: dict[str, Any], preflight: Evaluation) -> dict[str, Any]:
    return {
        "attempt_key": result["attempt_key"],
        "task_id": task["id"],
        "source_index": task["source_index"],
        "attempt": result["attempt"],
        "language": task["language"],
        "cwe": task["cwe"],
        "candidate": result["candidate"],
        "accepted": result.get("accepted", False),
        "rejection_reason": result.get("rejection_reason") or result.get("generation_error", ""),
        "evaluation": result.get("evaluation"),
        "reference_evaluation": preflight.to_dict(),
        "generation": result.get("generation"),
        "provider_model": result.get("provider_model"),
        "finish_reason": result.get("finish_reason"),
        "usage": result.get("usage"),
        "source_row": task["source_row"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default=DEFAULT_DATASET, help="HF dataset ID or local parquet/jsonl/json")
    parser.add_argument("--split", default="train")
    parser.add_argument("--output", type=Path, default=Path("outputs/vulnerable.jsonl"))
    parser.add_argument("--audit-output", type=Path, default=Path("outputs/all_attempts.jsonl"))
    parser.add_argument("--generation-workers", type=int, default=16)
    parser.add_argument("--eval-workers", type=int, default=8)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--attempts", type=int, default=1, help="candidates per source task")
    parser.add_argument("--temperature", type=float, default=0.8)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int, default=0, help="0 means all rows")
    parser.add_argument("--language", action="append", help="repeatable language filter")
    parser.add_argument("--cwe", action="append", help="repeatable CWE filter")
    parser.add_argument("--skip-preflight", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true", help="load, normalize, and preflight without model calls")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    for name in ("generation_workers", "eval_workers", "batch_size", "attempts"):
        if getattr(args, name) < 1:
            raise SystemExit(f"--{name.replace('_', '-')} must be >= 1")
    rows = load_rows(args.dataset, args.split)
    tasks: list[dict[str, Any]] = []
    skipped = 0
    languages = {value.lower() for value in args.language or []}
    cwes = {value.upper() for value in args.cwe or []}
    for index, row in enumerate(rows):
        try:
            task = normalize(row, index, args.split)
        except ValueError:
            skipped += 1
            continue
        if languages and task["language"] not in languages:
            continue
        if cwes and task["cwe"].upper() not in cwes:
            continue
        tasks.append(task)
    tasks = tasks[args.offset : args.offset + args.limit if args.limit else None]
    print(f"loaded={len(rows)} selected={len(tasks)} malformed={skipped}", flush=True)

    if not args.resume and not args.dry_run:
        for path in (args.output, args.audit_output):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")
    seen = read_seen(args.audit_output) if args.resume and not args.dry_run else set()
    accepted_total = attempted_total = 0

    for start in range(0, len(tasks), args.batch_size):
        batch = tasks[start : start + args.batch_size]
        if args.skip_preflight:
            preflight = {task["id"]: Evaluation(False, error="preflight skipped") for task in batch}
        else:
            pairs = parallel_map(
                lambda task: (task["id"], safe_evaluate(task["secure_solution"], task)),
                batch,
                args.eval_workers,
            )
            preflight = dict(pairs)
            batch = [task for task in batch if preflight[task["id"]].harness_ok and preflight[task["id"]].fully_functional and preflight[task["id"]].fully_secure]
        if args.dry_run:
            print(f"batch={start // args.batch_size + 1} preflight_passed={len(batch)}", flush=True)
            continue

        jobs = [(task, attempt) for task in batch for attempt in range(args.attempts) if f"{task['id']}:{attempt}" not in seen]
        generated: list[tuple[dict[str, Any], dict[str, Any]]] = []
        with ThreadPoolExecutor(max_workers=args.generation_workers) as pool:
            futures = {pool.submit(generate_one, task, attempt, args): task for task, attempt in jobs}
            for future in as_completed(futures):
                task = futures[future]
                result = future.result()
                result["generation"] = {
                    "model": MODEL,
                    "service_tier": SERVICE_TIER,
                    "prompt_version": PROMPT_VERSION,
                    "temperature": args.temperature,
                    "max_tokens": args.max_tokens,
                    "seed": args.seed,
                }
                generated.append((task, result))

        evaluated: list[tuple[dict[str, Any], dict[str, Any]]] = []
        failures = [(task, result) for task, result in generated if result["generation_error"]]
        candidates = [(task, result) for task, result in generated if not result["generation_error"]]
        with ThreadPoolExecutor(max_workers=args.eval_workers) as pool:
            futures = {pool.submit(evaluate_one, task, result): task for task, result in candidates}
            for future in as_completed(futures):
                evaluated.append((futures[future], future.result()))
        evaluated.extend(failures)
        evaluated.sort(key=lambda pair: (pair[0]["source_index"], pair[1]["attempt"]))

        audit_rows = [output_record(task, result, preflight[task["id"]]) for task, result in evaluated]
        accepted_rows = [row for row in audit_rows if row["accepted"]]
        append_jsonl(args.audit_output, audit_rows)
        append_jsonl(args.output, accepted_rows)
        attempted_total += len(audit_rows)
        accepted_total += len(accepted_rows)
        print(
            f"batch={start // args.batch_size + 1} attempted={len(audit_rows)} accepted={len(accepted_rows)}",
            flush=True,
        )

    print(f"done attempted={attempted_total} accepted={accepted_total} output={args.output}", flush=True)


if __name__ == "__main__":
    main()
