"""Score every finished extra-language generation (CWEval Go, BaxBench Go/PHP/Ruby/Rust) with benchmarks/run_plain_vllm.py --extra --operation evaluate.
Rescans every few minutes, so it picks up runs as the generation queues finish them. A run is scored once all its tasks x seeds are present."""
import json, subprocess, sys, time
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
PY = '/opt/conda/envs/vllm/bin/python'
N = dict(cweval=19, baxbench=168)
# (label, benchmark, directory) -- every place an extras run can land
def runs():
    import os
    sys.path.insert(0, str(Path(__file__).parent)); from _runs_def import runs as _r
    keep = set(filter(None, os.environ.get('ONLY_LABELS', '').split(',')))
    return [r for r in _r() if not keep or r[0] in keep]

def seeds_present(d):
    g = d / 'generations.jsonl'
    if not g.exists(): return None
    rows = []
    for l in g.open():
        try: rows.append(json.loads(l))
        except json.JSONDecodeError: pass
    by = {}
    for r in rows: by.setdefault(r['seed'], set()).add(r['case_id'])
    return by

def ready(d, b):
    by = seeds_present(d)
    if not by: return None
    full = sorted(s for s, ids in by.items() if len(ids) >= N[b])
    return full if full and len(full) == len(by) else None

BENCHES = set(sys.argv[1:]) or {'cweval', 'baxbench'}   # which benchmarks this instance scores
procs, k, scored = [], 0, set()
LIMIT = {'cweval': 3, 'baxbench': 3}
while True:
    todo = [(l, b, d) for l, b, d in runs() if b in BENCHES and d.exists() and not (d / 'summary.json').exists() and (str(d) not in scored)]
    for l, b, d in todo:
        seeds = ready(d, b)
        if not seeds: continue
        if sum(1 for p, bb in procs if bb == b and p.poll() is None) >= LIMIT[b]: continue
        rj = d / 'run.json'
        model = json.loads(rj.read_text()).get('model') if rj.exists() else l
        log = d.parent / f'{d.name}_score.log'
        k += 1; port = 40000 + (k * 300) % 20000   # stays inside the valid port range; at most a few jobs run at once
        cmd = [PY, str(REPO / 'benchmarks/run_plain_vllm.py'), '--model', model, '--model-label', l, '--benchmark', b, '--variant', 'repaired', '--out', str(d),
               '--seeds', *map(str, seeds), '--extra', '--operation', 'evaluate', '--baxbench-port-base', str(port), '--eval-workers', '16']
        env = dict(__import__('os').environ, PATH='/opt/conda/envs/cweval/go/bin:' + __import__('os').environ['PATH'], PYTHONDONTWRITEBYTECODE='1')
        procs.append((subprocess.Popen(cmd, stdout=log.open('a'), stderr=subprocess.STDOUT, cwd=REPO, env=env), b)); scored.add(str(d))
        print(time.strftime('%H:%M:%S'), 'scoring', l, b, 'seeds', seeds, flush=True)
    if not todo and all(p.poll() is not None for p, _ in procs) and not any(d.exists() and not (d / 'summary.json').exists() for _, _, d in runs()):
        break
    time.sleep(300)
print('SCORING_FINISHED', flush=True)
