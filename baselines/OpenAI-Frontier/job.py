"""One API model/benchmark/variant arm, one fresh sample per task."""
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib
import fcntl
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
CFG=json.loads((HERE/'configs/campaign.json').read_text())
os.environ['HF_HOME']='/workspace/hf_home'
sys.dont_write_bytecode=True
sys.path.insert(0,str(HERE/'evaluation'))
from run_plain_vllm import freeze_sources,build_cases,evaluate,summarize
from plain_eval.common import configure_paths,write_json,read_json


def identity(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def request_for(model,messages):
    request=dict(model=model,input=messages,max_output_tokens=CFG['max_output_tokens'],store=False)
    if model=='gpt-6.1-sol':request['reasoning']={'effort':CFG['sol_reasoning_effort']}
    else:request.update(temperature=CFG['gpt4o_temperature'],top_p=CFG['gpt4o_top_p'])
    return request


def generate(case,args,client):
    from openai import AuthenticationError,PermissionDeniedError,NotFoundError
    request=request_for(args.model,case['messages']);key=identity(request)
    path=args.out/'samples'/(identity(case['id'])+'.json')
    if path.exists():
        row=read_json(path)
        if row['request_sha256']!=key:raise ValueError('Saved sample belongs to another request')
        return row
    pilot=args.out/'pilot'
    started=time.monotonic()
    if (pilot/'request.json').exists() and read_json(pilot/'request.json')==request:
        raw=read_json(pilot/'response.json')
        answer=''.join(part.get('text','') for item in raw.get('output',[]) if item.get('type')=='message'
                       for part in item.get('content',[]) if part.get('type')=='output_text')
    else:
        try:
            response=client.responses.create(**request,extra_headers={'X-Client-Request-Id':key})
        except (AuthenticationError,PermissionDeniedError,NotFoundError) as exc:
            raise RuntimeError(f'API/model access failed ({type(exc).__name__}); no model substitution') from None
        except Exception as exc:
            raise RuntimeError(f'API request failed after retries ({type(exc).__name__}); resume saved samples') from None
        raw=response.model_dump(mode='json');answer=response.output_text or ''
    write_json(args.out/'responses'/(identity(case['id'])+'.json'),raw)
    usage=raw.get('usage') or {}
    row=dict(case_id=case['id'],seed=42,sample_index=0,api_seed=None,
        status='completed' if answer.strip() else 'failed',answer=answer,raw=answer,reasoning='',
        model=args.model,returned_model=raw.get('model'),request_sha256=key,response_id=raw.get('id'),
        finish_reason=raw.get('status'),incomplete_details=raw.get('incomplete_details'),
        usage=usage,output_tokens=usage.get('output_tokens'),prompt_tokens=usage.get('input_tokens'),
        reasoning_effort=CFG['sol_reasoning_effort'] if args.model=='gpt-6.1-sol' else None,
        elapsed_seconds=time.monotonic()-started,retrieval=False,wait_forcing=False)
    write_json(path,row)
    return row


def main():
    p=argparse.ArgumentParser();p.add_argument('--model',choices=CFG['models'],required=True)
    p.add_argument('--variant',choices=CFG['variants'],required=True)
    p.add_argument('--benchmark',choices=CFG['benchmarks'],required=True)
    p.add_argument('--operation',choices=['generate','evaluate','pilot-evaluate'],required=True)
    p.add_argument('--api-workers',type=int,default=CFG['api_workers'])
    args=p.parse_args();args.out=HERE/'outputs'/args.model/args.variant/args.benchmark
    args.out.mkdir(exist_ok=True,parents=True)
    if args.operation=='generate':
        generation_lock=(args.out/'generation.lock').open('w')
        fcntl.flock(generation_lock,fcntl.LOCK_EX)
    args.benchmarks_root=HERE.parents[1]/'benchmarks'
    args.pins_dir=HERE/'evaluation/plain_eval';args.model_label=args.model
    args.eval_workers=CFG['eval_workers'];args.baxbench_port_base=CFG['port_bases'][args.model]
    args.seeds=[42]
    configure_paths()
    frozen=freeze_sources(args)
    cases=build_cases(frozen,args.benchmark)
    write_json(args.out/'cases.json',cases)
    settings=dict(model=args.model,variant=args.variant,benchmark=args.benchmark,
        repetitions=1,api_seed=None,max_output_tokens=CFG['max_output_tokens'],endpoint=CFG['endpoint'],
        reasoning_effort=CFG['sol_reasoning_effort'] if args.model=='gpt-6.1-sol' else None,
        temperature=CFG['gpt4o_temperature'] if args.model=='gpt-4o' else None,
        top_p=CFG['gpt4o_top_p'] if args.model=='gpt-4o' else None,cases_sha256=identity(cases))
    path=args.out/'api_config.json'
    if path.exists() and read_json(path)!=settings:raise ValueError('API campaign settings changed')
    write_json(path,settings)
    if args.operation in ['generate','pilot-evaluate']:
        from dotenv import dotenv_values
        from openai import OpenAI
        key=dotenv_values(HERE.parents[1]/'CodeGuarder_AE/.env').get('OPENAI_API_KEY') or os.environ.get('OPENAI_API_KEY')
        if not key:raise RuntimeError('OPENAI_API_KEY unavailable')
        client=OpenAI(api_key=key,base_url=CFG['endpoint'],timeout=1800,max_retries=5)
        selected=cases[:1] if args.operation=='pilot-evaluate' else cases
        with ThreadPoolExecutor(max_workers=args.api_workers) as pool:
            futures=[pool.submit(generate,c,args,client) for c in selected]
            completed=0
            for future in as_completed(futures):
                future.result();completed+=1
                if completed%10==0 or completed==len(selected):
                    write_json(args.out/'progress.json',dict(status='generating',completed=completed,total=len(selected)))
                    print(args.model,args.variant,args.benchmark,completed,'/',len(selected),flush=True)
        rows=[read_json(args.out/'samples'/(identity(c['id'])+'.json')) for c in selected]
        if args.operation=='generate':
            tmp=args.out/'generations.tmp';tmp.write_text(''.join(json.dumps(r)+'\n' for r in rows));tmp.replace(args.out/'generations.jsonl')
            write_json(args.out/'progress.json',dict(status='generated',completed=len(rows),total=len(cases)))
            return
        # Separate pilot scoring directory; the first API sample is retained for the full run.
        args.out=args.out/'pilot_evaluation';args.out.mkdir(exist_ok=True)
        import shutil
        if not (args.out/'frozen').exists():shutil.copytree(frozen,args.out/'frozen'/args.benchmark)
    else:
        rows=[json.loads(l) for l in (args.out/'generations.jsonl').open()]
        assert len(rows)==len(cases) and len({r['case_id'] for r in rows})==len(cases)
    scores=evaluate(args,rows)
    summarize(args,scores)
    if args.operation=='pilot-evaluate' and any(s['evaluator_failure'] for s in scores):
        raise RuntimeError('Pilot evaluator failed')
    write_json(args.out/'progress.json',dict(status='complete',completed=len(rows),total=len(rows)))


if __name__=='__main__':main()
