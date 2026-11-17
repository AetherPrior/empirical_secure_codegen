"""Rescore every finished extra-language CWEval (Go) run on the fuzzed benchmark: copies generations.jsonl to <run parent>/fuzzed_extra_cweval and evaluates with --fuzzed --slice extra."""
import json, os, shutil, subprocess, sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
REPO = Path(__file__).resolve().parents[2]; sys.path.insert(0, str(Path(__file__).parent))
from _runs_def import runs
PY = '/opt/conda/envs/vllm/bin/python'
def one(a):
    l, d = a; out = d.parent / 'fuzzed_extra_cweval'
    if (out / 'summary.json').exists(): return l, 'cached'
    out.mkdir(parents=True, exist_ok=True); shutil.copy(d / 'generations.jsonl', out / 'generations.jsonl')
    seeds = sorted({json.loads(x)['seed'] for x in (d / 'generations.jsonl').open() if x.strip()})
    rj = d / 'run.json'; model = json.loads(rj.read_text()).get('model') if rj.exists() else l
    env = dict(os.environ, PATH='/opt/conda/envs/cweval/go/bin:' + os.environ['PATH'], PYTHONDONTWRITEBYTECODE='1')
    r = subprocess.run([PY, 'benchmarks/run_plain_vllm.py', '--model', model, '--model-label', l, '--benchmark', 'cweval', '--variant', 'repaired', '--out', str(out),
        '--seeds', *map(str, seeds), '--slice', 'extra', '--fuzzed', '--operation', 'evaluate', '--eval-workers', '8'], stdout=(out / 'rescore.log').open('w'), stderr=subprocess.STDOUT, cwd=REPO, env=env)
    return l, r.returncode
todo = [(l, d) for l, b, d in runs() if b == 'cweval' and (d / 'generations.jsonl').exists() and (d / 'summary.json').exists()]
print(len(todo), 'runs', flush=True)
with ThreadPoolExecutor(int(sys.argv[1]) if len(sys.argv) > 1 else 3) as p:
    for l, rc in p.map(one, todo): print(l, rc, flush=True)
print('FUZZ_GO_FINISHED')
