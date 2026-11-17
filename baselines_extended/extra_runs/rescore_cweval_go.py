"""Rescore the CWEval Go runs whose first scoring ran without goimports on PATH (see evaluators.cweval). Only runs the poller already
handled (plus gpt-4o, which was scored by hand); the poller itself picks up the rest with the corrected scorer."""
import json, os, re, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from _runs_def import runs, REPO, PY
done = set(re.findall(r'scoring (\S+) cweval', (Path(__file__).parent / 'score.out').read_text())) | {'gpt-4o'}
def one(item):
    label, bench, d = item
    rj = d / 'run.json'; model = json.loads(rj.read_text()).get('model') if rj.exists() else label
    seeds = sorted({json.loads(l)['seed'] for l in (d / 'generations.jsonl').open()})
    r = subprocess.run([PY, str(REPO / 'benchmarks/run_plain_vllm.py'), '--model', model, '--model-label', label, '--benchmark', 'cweval', '--variant', 'repaired',
                        '--out', str(d), '--seeds', *map(str, seeds), '--extra', '--operation', 'evaluate', '--eval-workers', '16'],
                       stdout=(d.parent / 'extra_cweval_score.log').open('w'), stderr=subprocess.STDOUT, cwd=REPO, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))  # evaluators.cweval sets PATH itself
    return label, f'rc={r.returncode}'
items = [x for x in runs() if x[1] == 'cweval' and x[0] in done and (x[2] / 'generations.jsonl').exists() and not (x[2] / 'summary.json').exists()]
print(len(items), 'runs to rescore', flush=True)
with ThreadPoolExecutor(2) as pool:
    for label, status in pool.map(one, items): print(label, status, flush=True)
print('RESCORE_FINISHED', flush=True)
