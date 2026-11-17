"""Plain single-model vLLM generation + evaluation on original or repaired benchmarks.

No reasoning budgets, injection, retrieval, or Wait forcing: each prompt is sent
once per seed through ``LLM.chat`` and the model generates freely up to
``--max-tokens``. The final answer is the text after the last ``</think>`` (or
the whole output when the model emits no reasoning block).

Benchmarks come from ``--benchmarks-root`` (default: secure_reasoning/benchmarks):

    variant    cweval            baxbench            seccodeplt (data / evaluator)
    original   cweval/           baxbench/           seccodeplt/data + secode-eval/
    repaired   cweval_repaired/  baxbench_repaired/  secode-eval_repaired/

Self-contained: everything it needs lives in this folder (``plain_eval/``),
including the pinned container images used for evaluation (``--pins-dir``).

Examples (from the project root):
    CUDA_VISIBLE_DEVICES=0 $PY baselines/Qwen3-8B-base/evaluation/run_plain_vllm.py --model Qwen/Qwen3-8B \\
        --benchmark cweval --variant original --out results/plain/qwen3_8b_cweval_orig
    CUDA_VISIBLE_DEVICES=0,1 $PY baselines/Qwen3-8B-base/evaluation/run_plain_vllm.py --model /path/to/ckpt --tp 2 \\
        --benchmark seccodeplt --variant repaired --out results/plain/ckpt_sec_rep
    $PY baselines/Qwen3-8B-base/evaluation/run_plain_vllm.py ... --operation evaluate   # re-score existing generations
"""
import argparse
import ast
import json
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from plain_eval.common import bax_cases, configure_paths, cwe_cases, read_json, write_json  # noqa: E402

BENCHMARKS_ROOT = HERE.parents[2] / "benchmarks"
PINS = HERE / 'plain_eval'
SOURCES = {
    ('cweval', 'original'): 'cweval', ('cweval', 'repaired'): 'cweval_repaired',
    ('baxbench', 'original'): 'baxbench', ('baxbench', 'repaired'): 'baxbench_repaired',
}


# ---------------------------------------------------------------- sources
def freeze_sources(args):
    """Copy the chosen benchmark variant to <out>/frozen/<benchmark> once."""
    dest = args.out / 'frozen' / args.benchmark
    if dest.exists():
        return dest
    root, ignore = args.benchmarks_root, shutil.ignore_patterns('__pycache__', '*.pyc')
    if args.benchmark == 'cweval':
        shutil.copytree(root / SOURCES['cweval', args.variant], dest, ignore=ignore)
    elif args.benchmark == 'baxbench':
        src = root / SOURCES['baxbench', args.variant]
        dest.mkdir(parents=True)
        shutil.copytree(src / 'src', dest / 'src', ignore=ignore)
    else:
        evaluator = root / ('secode-eval' if args.variant == 'original' else 'secode-eval_repaired')
        data = root / ('seccodeplt' if args.variant == 'original' else 'secode-eval_repaired') / 'data'
        dest.mkdir(parents=True)
        for name in ('evaluate_dataset.py', 'helpers.py'):
            shutil.copy2(evaluator / name, dest / name)
        shutil.copytree(data, dest / 'data')
    return dest


def build_cases(bench, benchmark):
    if benchmark == 'cweval':
        return cwe_cases(bench)
    if benchmark == 'baxbench':
        return bax_cases(bench)
    from plain_eval.seccodeplt_prompt import create_single_prompt_natural
    rows = [json.loads(l) for l in (bench / 'data/insecure_coding.jsonl').open() if l.strip()]
    return [dict(id=str(r['id']), language='py', messages=[dict(role='user', content=create_single_prompt_natural(
                r['task_description'], r['unittest']['setup']))])
            for r in rows if r.get('use_rule') is False]


# ---------------------------------------------------------------- generation
def split_answer(text):
    if '</think>' in text:
        reasoning, answer = text.rsplit('</think>', 1)
        return reasoning.split('<think>', 1)[-1].strip(), answer.strip()
    return '', text.strip()


def generate(args, cases):
    path = args.out / 'generations.jsonl'
    done = {}
    if path.exists():
        for line in path.open():
            r = json.loads(line)
            done[(r['case_id'], r['seed'])] = r
    todo = [(c, s) for c in cases for s in args.seeds if (c['id'], s) not in done]
    if todo:
        from vllm import LLM, SamplingParams
        llm = LLM(model=args.model, revision=args.revision, tensor_parallel_size=args.tp, dtype=args.dtype,
                  max_model_len=args.max_model_len, max_num_seqs=args.concurrency,
                  gpu_memory_utilization=args.gpu_memory_utilization, enable_prefix_caching=True,
                  trust_remote_code=args.trust_remote_code)
        params = [SamplingParams(temperature=args.temperature, top_p=args.top_p,
                                 max_tokens=args.max_tokens, seed=s) for _, s in todo]
        kwargs = {}
        if args.enable_thinking is not None:
            kwargs['chat_template_kwargs'] = dict(enable_thinking=args.enable_thinking)
        outputs = llm.chat([c['messages'] for c, _ in todo], params, use_tqdm=True, **kwargs)
        with path.open('a') as f:
            for (case, seed), out in zip(todo, outputs):
                o = out.outputs[0]
                reasoning, answer = split_answer(o.text)
                row = dict(case_id=case['id'], seed=seed, status='completed', answer=answer,
                           reasoning=reasoning, raw=o.text, finish_reason=o.finish_reason,
                           output_tokens=len(o.token_ids), prompt_tokens=len(out.prompt_token_ids))
                done[(case['id'], seed)] = row
                f.write(json.dumps(row) + '\n')
    return [done[(c['id'], s)] for c in cases for s in args.seeds]


# ---------------------------------------------------------------- evaluation
def seccodeplt_runner_source(benchmark):
    """Like evaluate_seccodeplt_container.runner_source, but the original evaluator
    has no _assert_result_equal (the repaired NumPy-aware comparison)."""
    source = (benchmark / 'evaluate_dataset.py').read_text()
    names = {'_indent_testcases_inside_test_method', '_assert_result_equal', 'execute_tests_w_traceback'}
    functions = {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body
                 if isinstance(n, ast.FunctionDef) and n.name in names}
    if not {'_indent_testcases_inside_test_method', 'execute_tests_w_traceback'} <= set(functions):
        raise ValueError('SecCodePLT test functions missing')
    header = ('import inspect, json, os, pickle, subprocess, sys, tempfile, time\n'
              'from pathlib import Path\nfrom typing import Any, Dict, Optional\n')
    entry = '''
payload = json.loads(Path('/work/input.json').read_text())
code, _ = extract_generated_code(payload['answer'])
row = payload['row']
result = execute_tests_w_traceback(code=code, setup=row['unittest']['setup'],
    testcases=row['unittest']['testcases'], func_name=row['task_description']['function_name'],
    install_requires=row.get('install_requires', []))
Path('/tmp/seccodeplt_result.json').write_text(json.dumps(result))
'''
    return header + '\n' + (benchmark / 'helpers.py').read_text() + '\n' + '\n\n'.join(functions.values()) + entry


def evaluate(args, rows):
    out, bench = args.out, args.out / 'frozen' / args.benchmark
    for name in ('container_images.json', 'preflight.json', 'seccodeplt_requirements.json'):
        if not (out / name).exists() and (args.pins_dir / name).exists():
            shutil.copy2(args.pins_dir / name, out / name)
    dest = out / 'evaluation'
    dest.mkdir(parents=True, exist_ok=True)
    model_label = args.model_label
    if args.benchmark == 'seccodeplt':
        import plain_eval.seccodeplt_eval as sec
        sec.runner_source = seccodeplt_runner_source
        lock = out / 'seccodeplt_requirements.json'
        scores = sec.evaluate(bench, rows, dest,
                              read_json(out / 'container_images.json')['baxbench']['python:3.12-alpine']['image_id'],
                              workers=args.eval_workers, requirements_lock=read_json(lock) if lock.exists() else None)
    else:
        from plain_eval import evaluators as evaluator
        write_json(out / 'config.json', dict(baxbench_port_base=args.baxbench_port_base,
                                            eval_workers=args.eval_workers))
        if args.benchmark == 'baxbench':
            write_json(out / 'campaign.json', dict(budgets=['plain'], models=[model_label]))
            from plain_eval.baxbench_runtime import repair_ports
            repair_ports(out, 'plain')
            evaluator.baxbench_port_base = lambda *_: args.baxbench_port_base
            scores = evaluator.baxbench(out, model_label, 'plain', rows, dest, workers=args.eval_workers)
        else:
            cwd = os.getcwd()
            try:
                scores = evaluator.cweval(out, model_label, 'plain', rows, dest, workers=args.eval_workers)
            finally:
                os.chdir(cwd)
    write_json(dest / 'scores.json', scores)
    return scores


def summarize(args, scores):
    per_seed = {}
    for s in scores:
        per_seed.setdefault(s['seed'], []).append(s)
    summary = dict(model=args.model, benchmark=args.benchmark, variant=args.variant, seeds={})
    for seed, ss in sorted(per_seed.items()):
        n = len(ss)
        summary['seeds'][seed] = dict(n=n, **{f'{k}@1': sum(x[k] for x in ss) / n
                                            for k in ('functionality', 'security', 'joint')},
                                      evaluator_failures=sum(x['evaluator_failure'] for x in ss))
    keys = ('functionality@1', 'security@1', 'joint@1')
    vals = list(summary['seeds'].values())
    summary['mean'] = {k: sum(v[k] for v in vals) / len(vals) for k in keys}
    if len(vals) > 1:
        summary['sd'] = {k: (sum((v[k] - summary['mean'][k]) ** 2 for v in vals) / (len(vals) - 1)) ** .5 for k in keys}
    write_json(args.out / 'summary.json', summary)
    print(json.dumps(summary, indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--model', required=True, help='HF id or local checkpoint path')
    p.add_argument('--revision', help='Pinned model revision')
    p.add_argument('--model-label', help='Short name used in evaluator metadata (default: basename of --model)')
    p.add_argument('--benchmark', choices=('cweval', 'baxbench', 'seccodeplt'), required=True)
    p.add_argument('--variant', choices=('original', 'repaired'), required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--operation', choices=('run', 'generate', 'evaluate'), default='run')
    p.add_argument('--benchmarks-root', type=Path, default=BENCHMARKS_ROOT)
    p.add_argument('--pins-dir', type=Path, default=PINS,
                   help='Directory with container_images.json, preflight.json, seccodeplt_requirements.json')
    p.add_argument('--seeds', type=int, nargs='+', default=[42, 43, 44])
    p.add_argument('--temperature', type=float, default=0.6)
    p.add_argument('--top-p', type=float, default=0.95)
    p.add_argument('--max-tokens', type=int, default=16384, help='Total generation length (reasoning + answer)')
    p.add_argument('--max-model-len', type=int, default=None)
    p.add_argument('--enable-thinking', action=argparse.BooleanOptionalAction, default=None,
                   help='Pass enable_thinking to the chat template (default: template default)')
    p.add_argument('--tp', type=int, default=1)
    p.add_argument('--dtype', default='bfloat16')
    p.add_argument('--concurrency', type=int, default=64)
    p.add_argument('--gpu-memory-utilization', type=float, default=0.9)
    p.add_argument('--trust-remote-code', action='store_true')
    p.add_argument('--limit', type=int, help='Only the first N tasks (smoke test)')
    p.add_argument('--languages', nargs='+', choices=('c', 'cpp', 'py', 'js'),
                   help='Restrict evaluation to these languages (default: all supported)')
    p.add_argument('--eval-workers', type=int, default=64, help='CPU/container workers for any benchmark')
    p.add_argument('--baxbench-port-base', type=int, default=26000)
    args = p.parse_args()
    if args.eval_workers < 1:
        p.error('--eval-workers must be positive')
    args.out = args.out.resolve()
    args.model_label = args.model_label or Path(args.model.rstrip('/')).name
    args.benchmarks_root = args.benchmarks_root.resolve()
    args.pins_dir = args.pins_dir.resolve()

    configure_paths()
    args.out.mkdir(parents=True, exist_ok=True)
    run_file = args.out / 'run.json'
    frozen = dict(model=args.model, benchmark=args.benchmark, variant=args.variant,
                  benchmarks_root=str(args.benchmarks_root))
    frozen['languages'] = sorted(set(args.languages)) if args.languages else None
    frozen['revision'] = args.revision
    frozen['method'] = 'plain'
    if run_file.exists() and {k: read_json(run_file).get(k) for k in frozen} != frozen:
        p.error(f'{args.out} was created for a different model/benchmark/variant; choose a new --out')
    write_json(run_file, dict(frozen, seeds=args.seeds, temperature=args.temperature, top_p=args.top_p,
                              max_tokens=args.max_tokens, enable_thinking=args.enable_thinking, limit=args.limit))

    cases = build_cases(freeze_sources(args), args.benchmark)
    if args.languages:
        cases = [c for c in cases if c['language'] in args.languages]
    cases = cases[:args.limit]
    if not cases:
        p.error('No tasks match the requested language selection')
    print(f'{args.benchmark}/{args.variant}: {len(cases)} tasks x {len(args.seeds)} seeds', flush=True)
    if args.operation == 'evaluate':
        path = args.out / 'generations.jsonl'
        by = {(r['case_id'], r['seed']): r for r in map(json.loads, path.open())}
        rows = [by[(c['id'], s)] for c in cases for s in args.seeds]
    else:
        rows = generate(args, cases)
    if args.operation != 'generate':
        summarize(args, evaluate(args, rows))


if __name__ == '__main__':
    main()
