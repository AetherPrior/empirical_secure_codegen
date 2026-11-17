"""Two API model campaigns; overlap generation with CPU scoring."""
from concurrent.futures import ThreadPoolExecutor
import fcntl
import json
import os
from pathlib import Path
import subprocess
import time

HERE=Path(__file__).resolve().parent
CFG=json.loads((HERE/'configs/campaign.json').read_text())
PY='/opt/conda/envs/vllm/bin/python'


def stage(model,variant,bench,operation):
    root=HERE/'outputs'/model;out=root/variant/bench
    out.mkdir(parents=True,exist_ok=True)
    status=out/f'{operation}_status.json'
    status.write_text(json.dumps(dict(status='running',started=time.time())))
    cmd=[PY,str(HERE/'job.py'),'--model',model,'--variant',variant,'--benchmark',bench,'--operation',operation]
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',HF_HOME='/workspace/hf_home',OMP_NUM_THREADS='4')
    with (out/f'{operation}.log').open('a') as log:
        result=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,cwd=HERE.parents[1])
    status.write_text(json.dumps(dict(status='complete' if result.returncode==0 else 'failed',returncode=result.returncode,finished=time.time())))
    if result.returncode:raise RuntimeError(f'{model}/{variant}/{bench}/{operation} failed; see log')


def model_worker(model):
    root=HERE/'outputs'/model;root.mkdir(exist_ok=True)
    with ThreadPoolExecutor(max_workers=1) as evaluation:
        futures=[]
        for variant in CFG['variants']:
            for bench in CFG['benchmarks']:
                for f in futures:
                    if f.done():f.result()
                status=dict(status='running',generation=dict(variant=variant,benchmark=bench))
                (root/'status.json').write_text(json.dumps(status,indent=2))
                stage(model,variant,bench,'generate')
                futures.append(evaluation.submit(stage,model,variant,bench,'evaluate'))
        (root/'status.json').write_text(json.dumps(dict(status='evaluating')))
        for f in futures:f.result()
    (root/'status.json').write_text(json.dumps(dict(status='complete')))


def main():
    lock=(HERE/'outputs/campaign.lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    status=HERE/'outputs/status.json'
    status.write_text(json.dumps(dict(status='running',samples_per_task=1,models=CFG['models'])))
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(model_worker,CFG['models']))
    except Exception as exc:
        status.write_text(json.dumps(dict(status='failed',error=str(exc))))
        raise
    status.write_text(json.dumps(dict(status='complete')))


if __name__=='__main__':main()
