"""CoSec generation for the plain benchmarks (original or repaired).

CoSec co-decodes a target model with a security expert (a LoRA on a small model),
so it cannot run on vLLM. This script replaces only the generation step of
benchmarks/run_plain_vllm.py. It reuses that runner's benchmark freezing and case
construction, and writes generations.jsonl in the same format, so scoring runs
through the unmodified evaluators:

    # 1. Build prompts once (Python 3.12, because the BaxBench sources require it)
    $PY312 baselines/cosec/run_cosec_plain.py --benchmark cweval --variant original \\
        --out results/cosec/cweval_original --prepare

    # 2. Generate, one process per shard, then merge (CoSec environment)
    $PY_COSEC baselines/cosec/run_cosec_plain.py --benchmark cweval --variant original \\
        --out results/cosec/cweval_original --shard-id 0 --num-shards 3
    $PY_COSEC baselines/cosec/run_cosec_plain.py --benchmark cweval --variant original \\
        --out results/cosec/cweval_original --num-shards 3 --merge

    # 3. Score (Python 3.12)
    $PY312 benchmarks/run_plain_vllm.py --model CoSec-Qwen3-8B --operation evaluate \\
        --benchmark cweval --variant original --out results/cosec/cweval_original

Each generation is seeded from --seeds alone, so its output does not depend on shard
order. --reuse-from copies rows from another run when the prompt is byte-identical,
which avoids regenerating prompts that a benchmark repair did not change.
"""
import argparse
import hashlib
import json
import sys
import time
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'benchmarks'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_plain_vllm as plain  # noqa: E402
from plain_eval.common import configure_paths, read_json, write_json  # noqa: E402


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


def load_models(args):
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(args.target_model)
    target = AutoModelForCausalLM.from_pretrained(args.target_model, device_map='auto', torch_dtype=torch.bfloat16)
    base = AutoModelForCausalLM.from_pretrained(args.lora_base, device_map='auto', torch_dtype=torch.bfloat16)
    expert = PeftModel.from_pretrained(base, args.lora_path)
    return tokenizer, target.eval(), expert.eval()


def generate_one(tokenizer, target, expert, case, seed, args):
    import torch
    from cosec_generate import cosec_sample

    prompt = tokenizer.apply_chat_template(case['messages'], tokenize=False, add_generation_prompt=True,
                                           enable_thinking=args.enable_thinking)
    input_ids = tokenizer(prompt, return_tensors='pt').input_ids.to(next(target.parameters()).device)
    stop_ids = [tokenizer.eos_token_id, tokenizer.convert_tokens_to_ids('<|endoftext|>')]
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    output = cosec_sample(target_model=target, expert_model=expert, input_ids=input_ids,
                          max_new_tokens=args.max_tokens, temperature=args.temperature, top_p=args.top_p,
                          expert_temperature=args.expert_temperature, expert_top_p=args.top_p,
                          threshold=args.threshold, num_return_sequences=1,
                          pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
                          eos_token_id=stop_ids, tokenizer=tokenizer)
    new_tokens = output[0, input_ids.shape[1]:].tolist()
    stopped = bool(new_tokens) and new_tokens[-1] in stop_ids
    text = tokenizer.decode(new_tokens, skip_special_tokens=True)
    reasoning, answer = plain.split_answer(text)
    return dict(case_id=case['id'], seed=seed, status='completed', answer=answer, reasoning=reasoning, raw=text,
                finish_reason='stop' if stopped else 'length', output_tokens=len(new_tokens),
                prompt_tokens=input_ids.shape[1], prompt_sha=prompt_sha(case))


def run_shard(args, cases):
    path = args.out / f'generations.shard{args.shard_id}.jsonl'
    done = {(r['case_id'], r['seed']) for r in read_rows(path)}
    reuse = {}
    if args.reuse_from:
        # Shard files are included so that a run stopped before its merge can still be reused.
        paths = [args.reuse_from / 'generations.jsonl', *sorted(args.reuse_from.glob('generations.shard*.jsonl'))]
        reuse = {(r['prompt_sha'], r['seed']): r for path in paths for r in read_rows(path)}
    todo = [(c, s) for i, c in enumerate(cases) for s in args.seeds
            if i % args.num_shards == args.shard_id and (c['id'], s) not in done]

    with path.open('a') as f:
        fresh = []
        for case, seed in todo:
            source = reuse.get((prompt_sha(case), seed))
            if source is None:
                fresh.append((case, seed))
            else:
                f.write(json.dumps(dict(source, case_id=case['id'], reused=True)) + '\n')
        f.flush()
        print(f'shard {args.shard_id}: {len(todo)} to do, {len(todo) - len(fresh)} reused, {len(fresh)} to generate',
              flush=True)
        if not fresh:
            return
        tokenizer, target, expert = load_models(args)
        start = time.time()
        for i, (case, seed) in enumerate(fresh, 1):
            try:
                row = generate_one(tokenizer, target, expert, case, seed, args)
            except Exception:  # Keep the shard going; --merge reports anything still missing.
                print(f'FAILED {case["id"]} seed={seed}\n{traceback.format_exc()}', flush=True)
                continue
            f.write(json.dumps(row) + '\n')
            f.flush()
            print(f'[{i}/{len(fresh)}] {case["id"]} seed={seed} tokens={row["output_tokens"]} '
                  f'{row["finish_reason"]} elapsed={time.time() - start:.0f}s', flush=True)


def merge(args, cases):
    by_key = {}
    for i in range(args.num_shards):
        for row in read_rows(args.out / f'generations.shard{i}.jsonl'):
            by_key[(row['case_id'], row['seed'])] = row
    keys = [(c['id'], s) for c in cases for s in args.seeds]
    missing = [k for k in keys if k not in by_key]
    if missing:
        sys.exit(f'{len(missing)} of {len(keys)} generations are missing, for example {missing[:5]}; '
                 'rerun the shards, which resume automatically')
    with (args.out / 'generations.jsonl').open('w') as f:
        for key in keys:
            f.write(json.dumps(by_key[key]) + '\n')
    rows = [by_key[k] for k in keys]
    truncated = sum(r['finish_reason'] == 'length' for r in rows)
    print(f'merged {len(rows)} generations; truncated at --max-tokens: {truncated}; '
          f'reused: {sum(bool(r.get("reused")) for r in rows)}')


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--benchmark', choices=('cweval', 'baxbench', 'seccodeplt'), required=True)
    p.add_argument('--variant', choices=('original', 'repaired'), required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--benchmarks-root', type=Path, default=REPO / 'benchmarks')
    p.add_argument('--target-model', default='/workspace/models/Qwen3-8B')
    p.add_argument('--lora-base', default='/workspace/models/Qwen3-0.6B')
    p.add_argument('--lora-path', default='/workspace/CoSec/trained/qwen3-0.6b/checkpoint-last-lora-only')
    p.add_argument('--seeds', type=int, nargs='+', default=[42, 43, 44])
    p.add_argument('--temperature', type=float, default=0.6, help='Default matches run_plain_vllm.py')
    p.add_argument('--expert-temperature', type=float, default=None, help='Default: same as --temperature')
    p.add_argument('--top-p', type=float, default=0.95)
    p.add_argument('--threshold', type=float, default=0.3, help='CoSec acceptance threshold')
    p.add_argument('--max-tokens', type=int, default=4096)
    p.add_argument('--enable-thinking', action=argparse.BooleanOptionalAction, default=False)
    p.add_argument('--limit', type=int, help='Only the first N tasks (smoke test)')
    p.add_argument('--shard-id', type=int, default=0)
    p.add_argument('--num-shards', type=int, default=1)
    p.add_argument('--reuse-from', type=Path, help='Earlier run whose rows are reused for identical prompts')
    p.add_argument('--prepare', action='store_true', help='Freeze sources and exit; run once before the shards')
    p.add_argument('--merge', action='store_true', help='Combine shard files into generations.jsonl')
    args = p.parse_args()
    args.out = args.out.resolve()
    args.benchmarks_root = args.benchmarks_root.resolve()
    if args.expert_temperature is None:
        args.expert_temperature = args.temperature

    configure_paths()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.prepare:
        # BaxBench sources need Python 3.12, while the CoSec models run in an older environment,
        # so the prompts are built once here and the shards only read cases.json.
        cases = plain.build_cases(plain.freeze_sources(args), args.benchmark)
        write_json(args.out / 'cases.json', cases)
        write_json(args.out / 'cosec_run.json', {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()
                                                 if k not in ('shard_id', 'prepare', 'merge')})
        print(f'{args.benchmark}/{args.variant}: prepared {len(cases)} tasks', flush=True)
        return
    cases = read_json(args.out / 'cases.json')[:args.limit]
    print(f'{args.benchmark}/{args.variant}: {len(cases)} tasks x {len(args.seeds)} seeds', flush=True)
    if args.merge:
        merge(args, cases)
    else:
        run_shard(args, cases)


if __name__ == '__main__':
    main()
