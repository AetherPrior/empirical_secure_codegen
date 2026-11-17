"""Qwen3-8B + original CodeGuarder, original and repaired benchmark campaign."""
import argparse
import fcntl
import json
import os
import subprocess
import time
from pathlib import Path

HERE=Path(__file__).resolve().parent
PY='/opt/conda/envs/vllm/bin/python'
EMBED_PY='/opt/conda/envs/cgp/bin/python'


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--smoke',action='store_true')
    p.add_argument('--dry-run',action='store_true')
    a=p.parse_args()
    cfg=json.loads((HERE/'configs/campaign.json').read_text())
    out=HERE/('outputs_smoke' if a.smoke else 'outputs')
    (out/'logs').mkdir(parents=True,exist_ok=True)
    lock=(HERE/'campaign.lock').open('w')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    env=dict(os.environ,CUDA_VISIBLE_DEVICES=str(cfg['gpu']),CUDA_DEVICE_ORDER='PCI_BUS_ID',
        HF_HOME=cfg['hf_home'],PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1',
        TOKENIZERS_PARALLELISM='false',OMP_NUM_THREADS='4',VLLM_USE_FLASHINFER_SAMPLER='0',
        VLLM_USE_DEEP_GEMM='0',VLLM_CACHE_ROOT=str(HERE/'outputs/cache/vllm'),
        TORCHINDUCTOR_CACHE_DIR=str(HERE/'outputs/cache/inductor'),TRITON_CACHE_DIR=str(HERE/'outputs/cache/triton'))
    jobs=[]
    for stage in ['plan','decompose','retrieve']:
        cmd=[EMBED_PY if stage=='retrieve' else PY,str(HERE/'prepare.py'),stage,'--out',str(out)]
        if stage=='plan' and a.smoke:cmd+=['--limit','1']
        jobs.append((stage,cmd))
    for variant in cfg['variants']:
        for bench in cfg['benchmarks']:
            if a.smoke and (variant,bench)!=('original','seccodeplt'):continue
            dest=out/variant/bench
            cmd=[PY,str(HERE/'evaluation/run_plain_vllm.py'),'--model',cfg['model'],
                 '--revision',cfg['model_revision'],'--model-label','codeguarder_qwen3_8b',
                 '--benchmark',bench,'--variant',variant,'--out',str(dest),
                 '--prepared-cases',str(dest/'prepared_cases.json'),
                 '--seeds',*map(str,[42] if a.smoke else cfg['seeds']),
                 '--tp','1','--baxbench-port-base','45000' if variant=='original' else '46000']
            for key in ['temperature','top_p','max_tokens','max_model_len','concurrency','eval_workers','gpu_memory_utilization']:
                cmd+=['--'+key.replace('_','-'),str(cfg[key])]
            cmd+=['--enable-thinking']
            if a.smoke:cmd+=['--limit','1']
            jobs.append((variant+'_'+bench,cmd))
    for name,cmd in jobs:
        print(name,cmd,flush=True)
        if a.dry_run:continue
        status=dict(stage=name,status='running',command=cmd,gpu=cfg['gpu'],hf_home=cfg['hf_home'])
        needs_gpu = name != 'plan'
        if name=='decompose' and (out/'queries.json').exists():
            needs_gpu=any(not (out/'decompositions'/f"{r['query_id']}.json").exists()
                          for r in json.loads((out/'queries.json').read_text()))
        if name=='retrieve' and (out/'jobs.json').exists():
            needs_gpu=any(not (Path(j['out'])/'prepared_cases.json').exists()
                          for j in json.loads((out/'jobs.json').read_text()))
        while needs_gpu:
            memory=subprocess.check_output(['nvidia-smi','--id='+str(cfg['gpu']),
                '--query-gpu=memory.free,memory.total','--format=csv,noheader,nounits'],text=True)
            free,total=map(int,memory.strip().split(','))
            required=int(total*cfg['gpu_memory_utilization'])+256
            if free>=required:break
            status.update(status='waiting_for_gpu',free_memory_mib=free,required_memory_mib=required)
            (out/'status.json').write_text(json.dumps(status,indent=2))
            print(f'{name}: waiting for GPU {cfg["gpu"]}: {free}/{required} MiB free/required',flush=True)
            time.sleep(15)
        status['status']='running'
        (out/'status.json').write_text(json.dumps(status,indent=2))
        with (out/f'logs/{name}.log').open('a') as log:
            result=subprocess.run(cmd,env=env,cwd=HERE.parents[1],stdout=log,stderr=subprocess.STDOUT)
        if result.returncode:
            status.update(status='failed',returncode=result.returncode)
            (out/'status.json').write_text(json.dumps(status,indent=2))
            raise SystemExit(result.returncode)
    if not a.dry_run:(out/'status.json').write_text(json.dumps(dict(status='complete')))


if __name__=='__main__':main()
