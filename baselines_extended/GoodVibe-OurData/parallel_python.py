"""Use idle GPUs for Python CWEval/BaxBench while SecCodePLT continues."""
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
import fcntl
import hashlib
import json
import os
import subprocess
import threading
import time

ROOT=Path(__file__).resolve().parent
LOCK=threading.Lock()
PY='/opt/conda/envs/vllm/bin/python'
state={}

def save():
    p=ROOT/'outputs/parallel_python_status.json';t=p.with_suffix('.tmp');t.write_text(json.dumps(state,indent=2)+'\n');t.replace(p)


def one(benchmark,gpu):
    from layout import checkpoint_path
    cfg=json.loads((ROOT/'configs/py.json').read_text());model=checkpoint_path(cfg)
    name=f'py_{benchmark}_py';out=ROOT/'outputs/repaired/evaluation'/name
    with LOCK:state[name]=dict(status='waiting_for_gpu',gpu=gpu);save()
    try:
        ready=0
        while ready<2:
            raw=subprocess.check_output(['nvidia-smi','--id='+str(gpu),'--query-gpu=memory.used,utilization.gpu','--format=csv,noheader,nounits'],text=True)
            memory,util=map(int,raw.strip().split(','));ready=ready+1 if memory<1024 and util<=5 else 0
            if ready<2:time.sleep(10)
        cache=ROOT/'outputs/cache'/f'parallel_gpu{gpu}';cache.mkdir(parents=True,exist_ok=True)
        env=dict(os.environ,CUDA_VISIBLE_DEVICES=str(gpu),CUDA_DEVICE_ORDER='PCI_BUS_ID',HF_HOME='/workspace/hf_home',
            PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1',TOKENIZERS_PARALLELISM='false',OMP_NUM_THREADS='4',
            VLLM_USE_FLASHINFER_SAMPLER='0',VLLM_USE_DEEP_GEMM='0',VLLM_CACHE_ROOT=str(cache/'vllm'),
            TORCHINDUCTOR_CACHE_DIR=str(cache/'inductor'),TRITON_CACHE_DIR=str(cache/'triton'))
        command=[PY,'-B',str(ROOT/'evaluation/run_plain_vllm.py'),'--model',str(model),
            '--model-label','goodvibe_ourdata_qwen3_8b_py','--benchmark',benchmark,'--variant','repaired',
            '--out',str(out),'--benchmarks-root',str(ROOT.parents[1]/'benchmarks'),'--languages','py',
            '--seeds','42','43','44','--enable-thinking','--tp','1','--temperature','0.6','--top-p','0.95',
            '--max-tokens','16384','--max-model-len','40960','--concurrency','256','--eval-workers','64','--gpu-memory-utilization','0.92']
        logs=ROOT/'outputs/repaired/logs';logs.mkdir(parents=True,exist_ok=True)
        for operation in ['generate','evaluate']:
            with (logs/f'{name}_parallel_{operation}.log').open('a') as log:
                proc=subprocess.Popen(command+['--operation',operation],env=env,cwd=ROOT.parents[1],stdout=log,stderr=subprocess.STDOUT)
                with LOCK:state[name].update(status=operation,pid=proc.pid);save()
                rc=proc.wait()
            if rc:raise RuntimeError(f'{operation} exited {rc}; see {name}_parallel_{operation}.log')
        scores=json.loads((out/'evaluation/scores.json').read_text());expected=(25 if benchmark=='cweval' else 112)*3
        assert len(scores)==expected and len({(r['case_id'],r['seed']) for r in scores})==expected
        if benchmark=='baxbench':
            for p in (out/'evaluation/artifacts').rglob('test.log'):
                text=p.read_text(errors='replace');assert 'failed to bind host port' not in text and 'port is already allocated' not in text
        proof={key+'_sha256':hashlib.sha256(p.read_bytes()).hexdigest() for key,p in {
            'generations':out/'generations.jsonl','scores':out/'evaluation/scores.json','summary':out/'summary.json'}.items()}
        (out/'parallel_complete.json').write_text(json.dumps(proof,indent=2)+'\n')
        subprocess.run([str(ROOT/'.venv/bin/python'),'-B',str(ROOT/'aggregate.py'),'--eval-config',str(ROOT/'configs/evaluation_repaired.json'),
            '--output-dir',str(ROOT/'outputs/repaired')],env=env,check=True)
        with LOCK:state[name].update(status='complete',samples=len(scores));save()
    except Exception as exc:
        with LOCK:state[name].update(status='failed',error=str(exc));save()
        raise


def main():
    handle=(ROOT/'outputs/parallel_python.lock').open('w');fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
    with ThreadPoolExecutor(max_workers=2) as pool:
        for f in as_completed([pool.submit(one,'cweval',1),pool.submit(one,'baxbench',3)]):f.result()

if __name__=='__main__':main()
