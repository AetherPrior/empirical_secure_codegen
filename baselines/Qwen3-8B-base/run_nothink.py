"""Run base and GoodVibe no-thinking campaigns, one variant per GPU."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
GOODVIBE = HERE.parent / 'GoodVibe'
OUT = HERE / 'outputs/nothink'


def worker(variant, gpu):
    commands = [
        ('base', [sys.executable, '-u', str(HERE / 'run.py'), '--variant', variant,
                  '--config', str(HERE / 'configs/campaign_nothink.json'),
                  '--output-dir', str(OUT)]),
        ('goodvibe', [sys.executable, '-u', str(GOODVIBE / 'run.py'), '--evaluation-only',
                      '--gpu', str(gpu), '--eval-config',
                      str(GOODVIBE / f'configs/evaluation_nothink_{variant}.json'),
                      '--output-dir', str(GOODVIBE / 'outputs/nothink' / variant)]),
    ]
    status = OUT / f'campaign_{variant}.json'
    for method, command in commands:
        status.write_text(json.dumps(dict(status='running', method=method, gpu=gpu,
                                          command=command, started=time.time()), indent=2))
        with (OUT / f'logs/{variant}_{method}.log').open('a') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
        if result.returncode:
            status.write_text(json.dumps(dict(status='failed', method=method,
                                              returncode=result.returncode), indent=2))
            raise RuntimeError(f'{variant}/{method} failed')
    status.write_text(json.dumps(dict(status='complete', finished=time.time()), indent=2))


if __name__ == '__main__':
    (OUT / 'logs').mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker, variant, gpu)
                   for variant, gpu in [('original', 2), ('repaired', 3)]]
        for future in futures:
            future.result()
