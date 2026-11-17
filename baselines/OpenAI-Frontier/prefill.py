"""Prepare repaired API samples while original-arm stragglers finish.

Per-arm generation locks and saved request hashes prevent duplicate samples
when the main campaign reaches these arms. Scoring stays with the main queue.
"""
import json
from pathlib import Path
import subprocess

HERE=Path(__file__).resolve().parent
for bench in ['seccodeplt','cweval','baxbench']:
    status=HERE/'outputs/prefill_status.json'
    status.write_text(json.dumps(dict(status='running',model='gpt-6.1-sol',variant='repaired',benchmark=bench,api_workers=48)))
    result=subprocess.run(['/opt/conda/envs/vllm/bin/python',str(HERE/'job.py'),
        '--model','gpt-6.1-sol','--variant','repaired','--benchmark',bench,'--operation','generate','--api-workers','48'])
    if result.returncode:
        status.write_text(json.dumps(dict(status='failed',benchmark=bench,returncode=result.returncode)))
        raise SystemExit(result.returncode)
status.write_text(json.dumps(dict(status='complete')))
