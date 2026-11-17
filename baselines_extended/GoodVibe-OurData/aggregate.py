"""Pool task-level scores into one result per benchmark, across languages."""
import fcntl
import argparse
from pathlib import Path
import json
import statistics
from layout import STATE


def pooled_summary(rows, seeds):
    keys = [(r['case_id'], r['seed']) for r in rows]
    if len(keys) != len(set(keys)):
        raise ValueError('Duplicate case/seed in pooled scores')
    result = {'seeds': {}}
    for seed in seeds:
        samples = [r for r in rows if r['seed'] == seed]
        if not samples:
            raise ValueError(f'Missing seed {seed}')
        result['seeds'][seed] = dict(n=len(samples), evaluator_failures=sum(r['evaluator_failure'] for r in samples),
            **{k+'@1': sum(r[k] for r in samples)/len(samples) for k in ['functionality', 'security', 'joint']})
    metrics = ['functionality@1', 'security@1', 'joint@1']
    result['mean'] = {k: statistics.mean(s[k] for s in result['seeds'].values()) for k in metrics}
    if len(seeds) > 1:
        result['sd'] = {k: statistics.stdev(s[k] for s in result['seeds'].values()) for k in metrics}
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--eval-config', type=Path, default=STATE/'configs/evaluation.json')
    parser.add_argument('--output-dir', type=Path, default=STATE/'outputs')
    args = parser.parse_args()
    root = args.output_dir.resolve()
    if not root.is_relative_to(STATE):
        parser.error('Outputs must stay within baselines/GoodVibe')
    cfg = json.loads(args.eval_config.read_text())
    output = root/'combined'
    output.mkdir(parents=True, exist_ok=True)
    with (output/'aggregate.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        status = {}
        for bench, expected in [('seccodeplt', 819), ('cweval', 100), ('baxbench', 224)]:
            rows, missing = [], []
            jobs = [j for j in cfg['jobs'] if j['benchmark'] == bench]
            if not jobs:
                continue
            for job in jobs:
                name = f"{job['checkpoint']}_{bench}_{'_'.join(job['languages'])}"
                path = root/'evaluation'/name/'evaluation/scores.json'
                if not path.exists():
                    missing.append(name)
                else:
                    run = json.loads((path.parents[1]/'run.json').read_text())
                    if run['variant'] != cfg['variant']:
                        raise ValueError(f'Variant mismatch for {name}')
                    rows.extend(json.loads(path.read_text()))
            if missing:
                status[bench] = dict(status='pending', missing=missing)
                continue
            summary = pooled_summary(rows, cfg['seeds'])
            if any(s['n'] != expected for s in summary['seeds'].values()):
                raise ValueError(f'Incomplete coverage for {bench}')
            summary.update(benchmark=bench, variant=cfg['variant'], checkpoint_routing=jobs)
            for filename, value in [(f'{bench}_summary.json', summary), (f'{bench}_scores.json', rows)]:
                target = output/filename
                tmp = target.with_suffix('.tmp')
                tmp.write_text(json.dumps(value, indent=2)+'\n')
                tmp.replace(target)
            status[bench] = dict(status='complete', summary=f'{bench}_summary.json')
        target = output/'status.json'
        tmp = target.with_suffix('.tmp')
        tmp.write_text(json.dumps(status, indent=2)+'\n')
        tmp.replace(target)


if __name__ == '__main__':
    main()
