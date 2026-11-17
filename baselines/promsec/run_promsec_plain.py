"""PromSec on the plain benchmarks (original or repaired), Python tasks only.

The first generation uses the same prompts as benchmarks/run_plain_vllm.py. Tasks Bandit
flags then go through PromSec's vet loop, reusing vet_code from run_promsec_secodeplt.py
unchanged. All LLM calls go to vLLM servers, and scoring uses the runner's evaluators:

    # 1. Build prompts (Python 3.12, because the BaxBench sources require it)
    $PY312 baselines/promsec/run_promsec_plain.py --benchmark cweval --variant original \\
        --out results/promsec/cweval_original --prepare

    # 2. Generate against running vLLM servers (PromSec environment)
    $PY_PROMSEC baselines/promsec/run_promsec_plain.py --benchmark cweval --variant original \\
        --out results/promsec/cweval_original --api-bases http://localhost:8100

    # 3. Score (Python 3.12)
    $PY312 baselines/promsec/run_promsec_plain.py --benchmark cweval --variant original \\
        --out results/promsec/cweval_original --evaluate

launch_all.sh runs all three and manages the servers. Rerunning step 2 resumes. Bandit only
scans Python, so non-Python tasks are left out. Multi-file answers (Django) skip the vet loop
because it regenerates a single file; those rows have vet_skipped set.
"""
import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'benchmarks'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_plain_vllm as plain  # noqa: E402
from plain_eval.common import configure_paths, read_json, write_json  # noqa: E402


def is_python(case, benchmark):
    return '/py/' in case['id'] if benchmark == 'cweval' else case['language'] == 'py'


def prompt_sha(case):
    return hashlib.sha256(json.dumps(case['messages'], sort_keys=True).encode()).hexdigest()


def read_rows(path):
    if not Path(path).exists():
        return []
    rows = []
    for line in Path(path).open():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:  # A killed process can leave a partial last line.
            continue
    return rows


def extract_code(answer, benchmark, remove_markdown):
    if benchmark == 'baxbench':
        match = re.search(r'<CODE>\n?(.*?)\n?</CODE>', answer, re.DOTALL)
        return match.group(1) if match else answer
    return remove_markdown(answer)


def wrap_code(code, benchmark):
    return f'<CODE>\n{code}\n</CODE>' if benchmark == 'baxbench' else f'```python\n{code}\n```'


class Client:
    """One task's LLM calls. Each call gets its own seed, derived from the task's seed."""

    def __init__(self, base, args, seed):
        self.base, self.args, self.seed = base, args, seed
        self.calls, self.prompt_tokens, self.output_tokens, self.truncated = 0, 0, 0, 0

    def chat(self, messages):
        import requests
        body = dict(model=self.args.target_model, messages=messages, temperature=self.args.temperature,
                    top_p=self.args.top_p, max_tokens=self.args.max_tokens, seed=self.seed + 1000 * self.calls,
                    chat_template_kwargs=dict(enable_thinking=self.args.enable_thinking))
        self.calls += 1
        for attempt in range(3):
            response = requests.post(f'{self.base}/v1/chat/completions', json=body, timeout=1800)
            if response.status_code < 500:
                break
            time.sleep(5 * (attempt + 1))
        response.raise_for_status()
        data = response.json()
        choice = data['choices'][0]
        self.prompt_tokens += data['usage']['prompt_tokens']
        self.output_tokens += data['usage']['completion_tokens']
        self.truncated += choice['finish_reason'] == 'length'
        return choice['message']['content'] or '', choice['finish_reason'], data['usage']


def load_promsec(args):
    """Import the vet loop unchanged, replacing only its LLM call and its shared Bandit file."""
    import torch
    import run_promsec_secodeplt as promsec

    torch.set_num_threads(1)
    generator = promsec.Generator(promsec.IN_FEATS, promsec.HIDDEN_FEATS, promsec.OUT_FEATS)
    generator.load_state_dict(torch.load(args.generator_weights, map_location='cpu'))
    generator.eval()

    original_vcs = promsec.calculate_vcs

    def calculate_vcs(code, code_filename=None):
        with tempfile.TemporaryDirectory() as folder:
            return original_vcs(code, os.path.join(folder, 'code.py'))

    def get_completion(client, tokenizer, prompt, max_new_tokens=None):
        return client.chat([dict(role='user', content=prompt)])[0]

    promsec.calculate_vcs = calculate_vcs
    promsec.get_completion = get_completion
    return promsec, generator


def generate_one(promsec, generator, case, seed, base, args):
    from sklearn.preprocessing import LabelEncoder

    client = Client(base, args, seed)
    text, finish_reason, usage = client.chat(case['messages'])
    reasoning, answer = plain.split_answer(text)
    row = dict(case_id=case['id'], seed=seed, status='completed', answer=answer, reasoning=reasoning, raw=text,
               finish_reason=finish_reason, output_tokens=usage['completion_tokens'],
               prompt_tokens=usage['prompt_tokens'], prompt_sha=prompt_sha(case), initial_answer=answer,
               iterations_used=0, vet_skipped=False, vet_error=None)

    code = extract_code(answer, args.benchmark, promsec.remove_markdown)
    k, cwes = promsec.calculate_vcs(code)
    row.update(initial_cwes=cwes, final_cwes=cwes)
    if '<FILEPATH>' in answer:
        row['vet_skipped'] = True
    else:
        encoder = LabelEncoder()
        graph = promsec.code_to_pyg(code, encoder)
        current = code
        for iteration in range(args.iter_num if graph is not None else 0):
            if k == 0:
                break
            try:
                current, _, graph = promsec.vet_code(client, None, generator, 'cpu', current, graph, encoder)
            except Exception as exc:  # Same as the May loop: stop and keep the latest code.
                row['vet_error'] = f'{type(exc).__name__}: {exc}'[:500]
                break
            k, cwes = promsec.calculate_vcs(current)
            row.update(iterations_used=iteration + 1, final_cwes=cwes)
        if row['iterations_used']:
            row['answer'] = wrap_code(current, args.benchmark)
    row.update(llm_calls=client.calls, total_output_tokens=client.output_tokens, truncated_calls=client.truncated)
    return row


def run_generation(args, cases):
    path = args.out / 'generations.partial.jsonl'
    done = {(r['case_id'], r['seed']) for r in read_rows(path)}
    reuse = {}
    if args.reuse_from:
        for source in (args.reuse_from / 'generations.jsonl', args.reuse_from / 'generations.partial.jsonl'):
            reuse.update({(r['prompt_sha'], r['seed']): r for r in read_rows(source)})
    todo = [(c, s) for c in cases for s in args.seeds if (c['id'], s) not in done]
    lock = threading.Lock()

    with path.open('a') as f:
        fresh = []
        for case, seed in todo:
            source = reuse.get((prompt_sha(case), seed))
            if source is None:
                fresh.append((case, seed))
            else:
                f.write(json.dumps(dict(source, case_id=case['id'], reused=True)) + '\n')
        f.flush()
        print(f'{len(todo)} to do, {len(todo) - len(fresh)} reused, {len(fresh)} to generate', flush=True)
        if not fresh:
            return

        promsec, generator = load_promsec(args)
        start = time.time()

        def work(index, case, seed):
            base = args.api_bases[index % len(args.api_bases)]
            return generate_one(promsec, generator, case, seed, base, args)

        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {pool.submit(work, i, c, s): (c['id'], s) for i, (c, s) in enumerate(fresh)}
            for count, future in enumerate(as_completed(futures), 1):
                case_id, seed = futures[future]
                try:
                    row = future.result()
                except Exception:  # Keep going; merge reports anything still missing.
                    print(f'FAILED {case_id} seed={seed}\n{traceback.format_exc()}', flush=True)
                    continue
                with lock:
                    f.write(json.dumps(row) + '\n')
                    f.flush()
                print(f'[{count}/{len(fresh)}] {case_id} seed={seed} iterations={row["iterations_used"]} '
                      f'calls={row["llm_calls"]} elapsed={time.time() - start:.0f}s', flush=True)


def merge(args, cases):
    by_key = {(r['case_id'], r['seed']): r for r in read_rows(args.out / 'generations.partial.jsonl')}
    keys = [(c['id'], s) for c in cases for s in args.seeds]
    missing = [k for k in keys if k not in by_key]
    if missing:
        sys.exit(f'{len(missing)} of {len(keys)} generations are missing, for example {missing[:5]}; '
                 'rerun, which resumes automatically')
    rows = [by_key[k] for k in keys]
    with (args.out / 'generations.jsonl').open('w') as f:
        for row in rows:
            f.write(json.dumps(row) + '\n')
    print(f'merged {len(rows)} generations; vetted: {sum(r["iterations_used"] > 0 for r in rows)}; '
          f'vet skipped: {sum(r["vet_skipped"] for r in rows)}; vet errors: {sum(bool(r["vet_error"]) for r in rows)}; '
          f'truncated first generations: {sum(r["finish_reason"] == "length" for r in rows)}; '
          f'reused: {sum(bool(r.get("reused")) for r in rows)}')


def exits_on_import(code):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(statement, ast.If) and '__name__' in ast.dump(statement.test):
            continue
        for node in ast.walk(statement):
            if isinstance(node, ast.Call) and getattr(node.func, 'attr', getattr(node.func, 'id', '')) in ('exit', 'quit'):
                return True
    return False


def contain_import_exit(answer):
    """pytest does not catch SystemExit during collection, so one generated module calling exit() on
    import aborts the session and loses every task of that seed. Raising ImportError instead fails
    only that task, like any other module that cannot be imported."""
    def wrap(match):
        code = match.group(1)
        if not exits_on_import(code):
            return match.group(0)
        return ('```python\ntry:\n    exec(' + repr(code) + ', globals())\nexcept SystemExit as exc:\n'
                "    raise ImportError('generated code exited on import') from exc\n```")
    return re.sub(r'```python\n(.*?)```', wrap, answer, flags=re.S)


def evaluate(args, cases):
    by_key = {(r['case_id'], r['seed']): r for r in read_rows(args.out / 'generations.jsonl')}
    rows = [dict(by_key[(c['id'], s)]) for c in cases for s in args.seeds]
    if args.column != 'answer':
        rows = [dict(r, answer=r[args.column]) for r in rows]
    if args.benchmark == 'cweval':
        rows = [dict(r, answer=contain_import_exit(r['answer'])) for r in rows]
    plain.summarize(args, plain.evaluate(args, rows))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--benchmark', choices=('cweval', 'baxbench', 'seccodeplt'), required=True)
    p.add_argument('--variant', choices=('original', 'repaired'), required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--benchmarks-root', type=Path, default=REPO / 'benchmarks')
    p.add_argument('--pins-dir', type=Path, default=REPO / 'benchmarks' / 'plain_eval')
    p.add_argument('--target-model', default='/workspace/models/Qwen3-8B')
    p.add_argument('--generator-weights', default='/workspace/PromSec/trained_generator_model.pt')
    p.add_argument('--api-bases', nargs='+', default=['http://localhost:8100'])
    p.add_argument('--seeds', type=int, nargs='+', default=[42, 43, 44])
    p.add_argument('--temperature', type=float, default=0.6)
    p.add_argument('--top-p', type=float, default=0.95)
    p.add_argument('--max-tokens', type=int, default=4096)
    p.add_argument('--enable-thinking', action=argparse.BooleanOptionalAction, default=False)
    p.add_argument('--iter-num', type=int, default=20, help='Maximum vet iterations per task')
    p.add_argument('--concurrency', type=int, default=64)
    p.add_argument('--limit', type=int, help='Only the first N Python tasks (smoke test)')
    p.add_argument('--reuse-from', type=Path, help='Earlier run whose rows are reused for identical prompts')
    p.add_argument('--prepare', action='store_true', help='Freeze sources and exit')
    p.add_argument('--merge-only', action='store_true', help='Combine finished rows into generations.jsonl')
    p.add_argument('--evaluate', action='store_true', help='Score generations.jsonl')
    p.add_argument('--column', default='answer', help='Row field to score; initial_answer scores the first generation')
    p.add_argument('--model-label', default='PromSec-Qwen3-8B')
    p.add_argument('--eval-workers', type=int, default=64)
    p.add_argument('--baxbench-port-base', type=int, default=27000)
    args = p.parse_args()
    args.out = args.out.resolve()
    args.benchmarks_root = args.benchmarks_root.resolve()
    args.pins_dir = args.pins_dir.resolve()
    args.model = args.model_label  # plain.summarize records this name.

    configure_paths()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.prepare:
        cases = [c for c in plain.build_cases(plain.freeze_sources(args), args.benchmark)
                 if is_python(c, args.benchmark)]
        write_json(args.out / 'cases.json', cases)
        write_json(args.out / 'promsec_run.json',
                   {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()
                    if k not in ('prepare', 'merge_only', 'evaluate')})
        print(f'{args.benchmark}/{args.variant}: prepared {len(cases)} Python tasks', flush=True)
        return
    cases = read_json(args.out / 'cases.json')[:args.limit]
    print(f'{args.benchmark}/{args.variant}: {len(cases)} tasks x {len(args.seeds)} seeds', flush=True)
    if args.evaluate:
        evaluate(args, cases)
    elif args.merge_only:
        merge(args, cases)
    else:
        run_generation(args, cases)


if __name__ == '__main__':
    main()
