"""Train GoodVibe on local pairs, then evaluate repaired benchmarks."""
from concurrent.futures import ThreadPoolExecutor,as_completed
import fcntl
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from datetime import datetime,timezone

HERE=Path(__file__).resolve().parent
WORKSPACE=HERE.parents[1]
TRAIN=HERE/'.venv/bin/python'
EVAL=Path('/opt/conda/envs/vllm/bin/python')
LOCK=threading.Lock()
ROUTES={'c':[('cweval','c')],'cpp':[('cweval','cpp')],
        'py':[('seccodeplt','py'),('cweval','py'),('baxbench','py')],
        'js':[('cweval','js'),('baxbench','js')]}


def now():return datetime.now(timezone.utc).isoformat()


def write(p,obj):
    p.parent.mkdir(parents=True,exist_ok=True);t=p.with_suffix('.tmp')
    t.write_text(json.dumps(obj,indent=2)+'\n');t.replace(p)


def main():
    out=HERE/'outputs';out.mkdir(exist_ok=True)
    handle=(out/'campaign.lock').open('w');fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
    state=dict(status='running',started=now(),dataset='our paired retrieval dataset',evaluation_variant='repaired',
        evaluation_thinking=True,languages={slug:dict(status='queued',gpu=i) for i,slug in enumerate(ROUTES)},evaluations={})
    eval_futures=[]
    def save():write(out/'status.json',state)
    def available(gpu):
        good=0
        while good<2:
            r=subprocess.check_output(['nvidia-smi','--id='+str(gpu),'--query-gpu=memory.used,utilization.gpu','--format=csv,noheader,nounits'],text=True)
            memory,util=map(int,r.strip().split(','));good=good+1 if memory<1024 and util<=5 else 0
            if good<2:time.sleep(15)
    def prior_evals_finished():
        paths=[WORKSPACE/'baselines'/n/'outputs/no_think_baxbench/status.json' for n in ['Qwen3-8B-base','GoodVibe']]
        paths += [WORKSPACE/'baselines_extended'/n/'outputs/repaired_campaign_status.json' for n in ['Outcome-Only-RL','Our-Retrieval']]
        for p in paths:
            if not p.exists():continue
            s=json.loads(p.read_text())
            if any(j['status'] not in ['complete','failed'] for j in s.get('jobs',[])):return False
        return True
    def run_stage(command,env,log):
        log.parent.mkdir(parents=True,exist_ok=True)
        with log.open('a') as f:
            proc=subprocess.Popen(command,cwd=WORKSPACE,env=env,stdout=f,stderr=subprocess.STDOUT)
            rc=proc.wait()
        if rc:raise RuntimeError(f'Exit {rc}; see {log}')
    def evaluate(name,command,env):
        try:
            with LOCK:state['evaluations'][name]=dict(status='waiting_for_cpu');save()
            while not prior_evals_finished():time.sleep(30)
            with LOCK:state['evaluations'][name].update(status='evaluating',started=now());save()
            run_stage(command+['--operation','evaluate'],env,out/'repaired/logs'/f'{name}_evaluate.log')
            dest=out/'repaired/evaluation'/name
            scores=json.loads((dest/'evaluation/scores.json').read_text())
            assert scores and len({(s['case_id'],s['seed']) for s in scores})==len(scores)
            bad=[]
            for p in (dest/'evaluation/artifacts').rglob('test.log'):
                s=p.read_text(errors='replace')
                if 'failed to bind host port' in s or 'port is already allocated' in s:bad.append(str(p))
            assert not bad,bad
            write(dest/'infrastructure_audit.json',dict(port_conflicts=bad))
            with LOCK:
                state['evaluations'][name].update(status='complete',finished=now(),samples=len(scores))
                save()
            subprocess.run([str(TRAIN),'-B',str(HERE/'aggregate.py'),'--eval-config',str(HERE/'configs/evaluation_repaired.json'),
                '--output-dir',str(out/'repaired')],cwd=WORKSPACE,env=env,check=True)
        except Exception as exc:
            with LOCK:state['evaluations'][name]=dict(status='failed',error=str(exc));save()
            print('EVALUATION FAILED',name,str(exc),flush=True)
    def language(slug,gpu,cpu):
        cfg=json.loads((HERE/'configs'/f'{slug}.json').read_text())
        cache=out/'cache'/f'gpu{gpu}'
        env=dict(os.environ,GOODVIBE_GPU=str(gpu),CUDA_VISIBLE_DEVICES=str(gpu),CUDA_DEVICE_ORDER='PCI_BUS_ID',
            HF_HOME='/workspace/hf_home',PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1',TOKENIZERS_PARALLELISM='false',OMP_NUM_THREADS='4',
            VLLM_USE_FLASHINFER_SAMPLER='0',VLLM_USE_DEEP_GEMM='0',VLLM_CACHE_ROOT=str(cache/'vllm'),
            TORCHINDUCTOR_CACHE_DIR=str(cache/'inductor'),TRITON_CACHE_DIR=str(cache/'triton'),HF_DATASETS_CACHE=str(cache/'datasets'))
        try:
            for stage in ['identify','tune']:
                with LOCK:state['languages'][slug].update(status='waiting_for_gpu',next_stage=stage);save()
                available(gpu)
                with LOCK:state['languages'][slug].update(status=stage,stage_started=now());save()
                run_stage([str(TRAIN),'-B',str(HERE/'train.py'),'--config',str(HERE/'configs'/f'{slug}.json'),'--stage',stage],
                    env,out/'logs'/f'{slug}_{stage}.log')
            from layout import checkpoint_path
            checkpoint=checkpoint_path(cfg);assert (checkpoint/'config.json').exists()
            with LOCK:state['languages'][slug].update(status='trained',checkpoint=str(checkpoint),finished=now());save()
            for bench,lang in ROUTES[slug]:
                name=f'{slug}_{bench}_{lang}';dest=out/'repaired/evaluation'/name
                with LOCK:state['evaluations'][name]=dict(status='waiting_for_generation',gpu=gpu);save()
                available(gpu)
                command=[str(EVAL),'-B',str(HERE/'evaluation/run_plain_vllm.py'),'--model',str(checkpoint),
                    '--model-label',f'goodvibe_ourdata_qwen3_8b_{slug}','--benchmark',bench,'--variant','repaired',
                    '--out',str(dest),'--benchmarks-root',str(WORKSPACE/'benchmarks'),'--languages',lang,
                    '--seeds','42','43','44','--enable-thinking','--tp','1','--temperature','0.6','--top-p','0.95',
                    '--max-tokens','16384','--max-model-len','40960','--concurrency','256','--eval-workers','64','--gpu-memory-utilization','0.92']
                with LOCK:state['evaluations'][name].update(status='generating',started=now());save()
                run_stage(command+['--operation','generate'],env,out/'repaired/logs'/f'{name}_generate.log')
                with LOCK:
                    state['evaluations'][name].update(status='generated');save()
                    eval_futures.append(cpu.submit(evaluate,name,command,env))
        except Exception as exc:
            with LOCK:state['languages'][slug].update(status='failed',error=str(exc));save()
            print('LANGUAGE FAILED',slug,str(exc),flush=True)
    with LOCK:save()
    with ThreadPoolExecutor(max_workers=2) as cpu:
        with ThreadPoolExecutor(max_workers=4) as gpu:
            for f in as_completed([gpu.submit(language,slug,i,cpu) for i,slug in enumerate(ROUTES)]):f.result()
        for f in as_completed(eval_futures):f.result()
    with LOCK:
        state.update(status='complete' if all(s['status']=='trained' for s in state['languages'].values()) and len(state['evaluations'])==7 and all(s['status']=='complete' for s in state['evaluations'].values()) else 'failed',finished=now())
        save()

if __name__=='__main__':main()
