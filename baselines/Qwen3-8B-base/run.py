"""Base Qwen3-8B on original/repaired benchmarks, with concurrent GPU workers."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
PY='/opt/conda/envs/vllm/bin/python'
CFG=json.loads((HERE/'configs/campaign.json').read_text())
OUTPUT=HERE/'outputs'


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value,indent=2)+'\n')
    tmp.replace(path)


def worker(spec,dry_run=False):
    variant=spec['variant'];out=OUTPUT/variant
    (out/'logs').mkdir(parents=True,exist_ok=True)
    lock=(out/'worker.lock').open('w')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    env=dict(os.environ,CUDA_VISIBLE_DEVICES=str(spec['gpu']),CUDA_DEVICE_ORDER='PCI_BUS_ID',
        HF_HOME=CFG['hf_home'],PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1',
        TOKENIZERS_PARALLELISM='false',OMP_NUM_THREADS='4',VLLM_USE_FLASHINFER_SAMPLER='0',
        VLLM_USE_DEEP_GEMM='0',VLLM_CACHE_ROOT=str(HERE/'outputs/cache/vllm'),
        TORCHINDUCTOR_CACHE_DIR=str(HERE/'outputs/cache/inductor'),TRITON_CACHE_DIR=str(HERE/'outputs/cache/triton'))
    def stage(bench,operation,command):
        status=out/f'{bench}_{operation}_status.json'
        save(status,dict(status='running',command=command,gpu=spec['gpu'],started=time.time()))
        with (out/f'logs/{bench}_{operation}.log').open('a') as log:
            result=subprocess.run(command,env=env,cwd=HERE.parents[1],stdout=log,stderr=subprocess.STDOUT)
        save(status,dict(status='complete' if result.returncode==0 else 'failed',returncode=result.returncode,finished=time.time()))
        if result.returncode:raise RuntimeError(f'{variant}/{bench}/{operation} failed; see log')
    futures=[]
    # One evaluation per GPU worker: up to 128 CPU/container workers total,
    # while generation advances independently on both GPUs.
    with ThreadPoolExecutor(max_workers=1) as pool:
        for bench in CFG['benchmarks']:
            cmd=[PY,str(HERE/'evaluation/run_plain_vllm.py'),'--model',CFG['model'],
                '--revision',CFG['model_revision'],'--model-label','qwen3_8b_base',
                '--benchmark',bench,'--variant',variant,'--out',str(out/bench),
                '--benchmarks-root',str(HERE.parents[1]/'benchmarks'),
                '--seeds',*map(str,CFG['seeds']),'--tp','1','--baxbench-port-base',str(spec['port_base'])]
            for key in ['temperature','top_p','max_tokens','max_model_len','concurrency','eval_workers','gpu_memory_utilization']:
                cmd+=['--'+key.replace('_','-'),str(CFG[key])]
            cmd+=['--enable-thinking' if CFG.get('enable_thinking', True) else '--no-enable-thinking']
            if dry_run:
                print(variant,bench,cmd,flush=True)
                continue
            for future in futures:
                if future.done():future.result()
            save(out/'status.json',dict(status='running',generation=bench,gpu=spec['gpu']))
            # A completed generation can be scored without waiting for GPU memory.
            generations=out/bench/'generations.jsonl'
            expected={'seccodeplt':819,'cweval':100,'baxbench':224}[bench]*len(CFG['seeds'])
            complete=generations.exists() and sum(1 for _ in generations.open())==expected
            while not complete:
                memory=subprocess.check_output(['nvidia-smi','--id='+str(spec['gpu']),
                    '--query-gpu=memory.free,memory.total','--format=csv,noheader,nounits'],text=True)
                free,total=map(int,memory.strip().split(','))
                if free>=int(total*CFG['gpu_memory_utilization'])+256:break
                save(out/'status.json',dict(status='waiting_for_gpu',generation=bench,gpu=spec['gpu'],free_memory_mib=free))
                time.sleep(15)
            stage(bench,'generate',cmd+['--operation','generate'])
            futures.append(pool.submit(stage,bench,'evaluate',cmd+['--operation','evaluate']))
        if not dry_run:
            save(out/'status.json',dict(status='evaluating',gpu=spec['gpu']))
            for future in futures:future.result()
            save(out/'status.json',dict(status='complete',gpu=spec['gpu']))


def main():
    global CFG, OUTPUT
    p=argparse.ArgumentParser()
    p.add_argument('--variant',choices=['original','repaired'])
    p.add_argument('--dry-run',action='store_true')
    p.add_argument('--config',type=Path,default=HERE/'configs/campaign.json')
    p.add_argument('--output-dir',type=Path,default=HERE/'outputs')
    a=p.parse_args()
    CFG=json.loads(a.config.read_text())
    OUTPUT=a.output_dir.resolve()
    if not OUTPUT.is_relative_to(HERE):
        p.error('Outputs must stay within baselines/Qwen3-8B-base')
    specs=[s for s in CFG['workers'] if not a.variant or s['variant']==a.variant]
    if a.variant or a.dry_run:
        try:
            for spec in specs:worker(spec,a.dry_run)
        except Exception as exc:
            save(OUTPUT/(a.variant or 'campaign')/'status.json',dict(status='failed',error=str(exc)))
            raise
        return
    out=OUTPUT
    (out/'logs').mkdir(parents=True,exist_ok=True)
    children=[]
    for spec in specs:
        log=(out/f"logs/{spec['variant']}_worker.log").open('a')
        proc=subprocess.Popen([sys.executable,'-u',str(HERE/'run.py'),'--variant',spec['variant'],
                               '--config',str(a.config.resolve()),'--output-dir',str(out)],
                              stdout=log,stderr=subprocess.STDOUT)
        log.close()
        children.append((spec,proc))
    save(out/'status.json',dict(status='running',workers=[dict(**s,pid=p.pid) for s,p in children]))
    results=[dict(**s,pid=p.pid,returncode=p.wait()) for s,p in children]
    save(out/'status.json',dict(status='complete' if all(r['returncode']==0 for r in results) else 'failed',workers=results))


if __name__=='__main__':main()
