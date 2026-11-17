"""Repaired outcome-RL and retrieval evaluation, four GPUs and two CPU workers."""
import csv
import fcntl
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime,timezone

HERE=Path(__file__).resolve().parent
WORKSPACE=HERE.parents[1]
ROOTS=[HERE,HERE.parent/'Our-Retrieval']
PY='/opt/conda/envs/vllm/bin/python'
LOCK=threading.Lock()


def now():return datetime.now(timezone.utc).isoformat()


def write(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True);t=p.with_name(p.name+'.resume.tmp')
    t.write_text(json.dumps(obj,indent=2)+'\n');t.replace(p)


def main():
    handle=(HERE/'outputs/campaign.lock').open('w');fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
    configs={r:json.loads((r/'configs/resume_evaluation.json').read_text()) for r in ROOTS}
    states={r:dict(status='starting',started=now(),scope='repaired only',enable_thinking=True,
                   jobs=[dict(j,status='queued') for j in configs[r]['jobs']]) for r in ROOTS}
    def save():
        for r,s in states.items():
            ss=[j['status'] for j in s['jobs']]
            s['status']='complete' if all(v=='complete' for v in ss) else 'failed' if 'failed' in ss else 'running'
            write(r/'outputs/repaired_campaign_status.json',s)
    def cmd(root,job,operation):
        cfg=configs[root]
        c=[PY,'-B',str(root/'evaluation/run_plain_vllm.py'),'--model',job['model'],'--model-label',job['model_label'],
            '--benchmark',job['benchmark'],'--variant','repaired','--out',job['out'],'--operation',operation,
            '--benchmarks-root',str(WORKSPACE/'benchmarks'),'--enable-thinking','--seeds',*map(str,cfg['seeds']),'--tp','1']
        for k in ['temperature','top_p','max_tokens','max_model_len','concurrency','eval_workers','gpu_memory_utilization']:
            c+=['--'+k.replace('_','-'),str(cfg[k])]
        if job['revision']:c+=['--revision',job['revision']]
        if job['prepared_cases']:c+=['--prepared-cases',job['prepared_cases']]
        return c
    def valid_scores(job):
        p=Path(job['out']);f=p/'evaluation/scores.json'
        if not f.exists() or not (p/'summary.json').exists():return False
        scores=json.loads(f.read_text())
        return len(scores)==job['expected_samples'] and len({(s['case_id'],s['seed']) for s in scores})==len(scores)
    def evaluate(root,job,env):
        try:
            # Avoid adding another 128 container workers while the already
            # authorized no-thinking evaluations are still using those slots.
            with LOCK:job.update(status='waiting_for_cpu_evaluation',evaluation_queued=now());save()
            while True:
                statuses=[]
                for name in ['Qwen3-8B-base','GoodVibe']:
                    p=WORKSPACE/'baselines'/name/'outputs/no_think_baxbench/status.json'
                    if p.exists():statuses.append(json.loads(p.read_text())['status'])
                if all(s in ['complete','failed'] for s in statuses):break
                time.sleep(20)
            out=Path(job['out'])
            with (out/'resume_evaluate.log').open('a') as log:
                proc=subprocess.Popen(cmd(root,job,'evaluate'),cwd=WORKSPACE,env=env,stdout=log,stderr=subprocess.STDOUT)
                with LOCK:job.update(status='evaluating',evaluation_pid=proc.pid,evaluation_started=now());save()
                rc=proc.wait()
            if rc:raise RuntimeError(f'Evaluation exited {rc}; see {out}/resume_evaluate.log')
            assert valid_scores(job),'Incomplete evaluation'
            if job['benchmark']=='baxbench':
                bad=[]
                for p in (out/'evaluation/artifacts').rglob('test.log'):
                    s=p.read_text(errors='replace')
                    if 'failed to bind host port' in s or 'port is already allocated' in s:bad.append(str(p))
                assert not bad,bad
                write(out/'infrastructure_audit.json',dict(port_conflicts=bad))
            with LOCK:job.update(status='complete',finished=now());save()
        except Exception as e:
            with LOCK:job.update(status='failed',error=str(e));save()
            print('EVALUATION FAILED',job['name'],str(e),flush=True)
    pending=queue.Queue()
    # Existing retrieval CWEval is retained. Its prepared inputs are not rebuilt.
    for root in reversed(ROOTS):
        for job in states[root]['jobs']:
            if valid_scores(job):job.update(status='complete',reused_existing_scores=True)
            else:pending.put((root,job))
    with LOCK:save()
    eval_futures=[]
    with ThreadPoolExecutor(max_workers=2) as cpu:
        def gpu_worker(index):
            while True:
                try:root,job=pending.get_nowait()
                except queue.Empty:return
                out=Path(job['out']);out.mkdir(exist_ok=True,parents=True)
                try:
                    complete=(out/'generations.jsonl').exists() and sum(1 for _ in (out/'generations.jsonl').open())==job['expected_samples']
                    if not complete:
                        with LOCK:job.update(status='waiting_for_gpu',gpu=index);save()
                        ready=0
                        while ready<2:
                            result=subprocess.check_output(['nvidia-smi','--id='+str(index),'--query-gpu=memory.used,utilization.gpu','--format=csv,noheader,nounits'],text=True)
                            memory,util=map(int,result.strip().split(','));ready=ready+1 if memory<1024 and util<=5 else 0
                            if ready<2:time.sleep(10)
                    cache=root/'outputs/cache/repaired_resume_700'/f'gpu{index}';cache.mkdir(exist_ok=True,parents=True)
                    env=dict(os.environ,CUDA_VISIBLE_DEVICES=str(index),CUDA_DEVICE_ORDER='PCI_BUS_ID',HF_HOME='/workspace/hf_home',
                        PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1',TOKENIZERS_PARALLELISM='false',OMP_NUM_THREADS='4',
                        VLLM_USE_FLASHINFER_SAMPLER='0',VLLM_USE_DEEP_GEMM='0',VLLM_CACHE_ROOT=str(cache/'vllm'),
                        TORCHINDUCTOR_CACHE_DIR=str(cache/'inductor'),TRITON_CACHE_DIR=str(cache/'triton'))
                    if not complete:
                        with (out/'resume_generate.log').open('a') as log:
                            proc=subprocess.Popen(cmd(root,job,'generate'),cwd=WORKSPACE,env=env,stdout=log,stderr=subprocess.STDOUT)
                            with LOCK:job.update(status='generating',generation_pid=proc.pid,generation_started=now());save()
                            rc=proc.wait()
                        if rc:raise RuntimeError(f'Generation exited {rc}; see {out}/resume_generate.log')
                    generated=[json.loads(l) for l in (out/'generations.jsonl').open()]
                    assert len(generated)==job['expected_samples']
                    assert len({(r['case_id'],r['seed']) for r in generated})==len(generated)
                    assert json.loads((out/'run.json').read_text())['enable_thinking'] is True
                    with LOCK:
                        job.update(status='generated',generation_finished=now(),samples_generated=len(generated));save()
                        eval_futures.append(cpu.submit(evaluate,root,job,env))
                except Exception as e:
                    with LOCK:job.update(status='failed',error=str(e));save()
                    print('GENERATION FAILED',job['name'],str(e),flush=True)
                pending.task_done()
        with ThreadPoolExecutor(max_workers=4) as gpu:
            for f in as_completed([gpu.submit(gpu_worker,i) for i in range(4)]):f.result()
        for f in as_completed(eval_futures):f.result()
    with LOCK:
        for s in states.values():s['finished']=now()
        save()

if __name__=='__main__':main()
