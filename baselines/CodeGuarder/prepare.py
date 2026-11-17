"""Freeze benchmark inputs, decompose queries, then retrieve original knowledge."""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
CFG = json.loads((HERE/'configs/campaign.json').read_text())
os.environ['HF_HOME'] = CFG['hf_home']
os.environ['CUDA_VISIBLE_DEVICES'] = str(CFG['gpu'])
os.environ['CUDA_DEVICE_ORDER'] = 'PCI_BUS_ID'
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
os.environ['VLLM_USE_FLASHINFER_SAMPLER'] = '0'
os.environ['VLLM_USE_DEEP_GEMM'] = '0'
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE/'evaluation'))
from adapter import augment, parse_modules, select_knowledge


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')
    tmp.replace(path)


def plan(out, limit):
    from run_plain_vllm import freeze_sources, build_cases
    from plain_eval.common import configure_paths
    configure_paths()
    jobs, queries = [], {}
    for variant in CFG['variants']:
        for benchmark in CFG['benchmarks']:
            dest = out/variant/benchmark
            dest.mkdir(parents=True, exist_ok=True)
            args = SimpleNamespace(out=dest, benchmarks_root=HERE.parents[1]/'benchmarks',
                                   benchmark=benchmark, variant=variant)
            frozen = freeze_sources(args)
            # Import each frozen variant independently in a subprocess (see CLI).
            jobs.append(dict(variant=variant, benchmark=benchmark, out=str(dest)))
    save(out/'jobs.json', jobs)
    # Cases are built by separate processes to avoid Python module reuse across variants.
    import subprocess
    for job in jobs:
        command = [sys.executable, str(Path(__file__).resolve()), 'cases', '--out', str(out),
                   '--variant', job['variant'], '--benchmark', job['benchmark']]
        if limit:
            command += ['--limit', str(limit)]
        subprocess.run(command, check=True)
        cases = json.loads((Path(job['out'])/'cases.json').read_text())
        for case in cases:
            queries[case['query_id']] = dict(query_id=case['query_id'], query=case['retrieval_query'], language=case['language'])
    save(out/'queries.json', list(queries.values()))
    print(f'{len(queries)} unique queries across {len(jobs)} benchmark/variant jobs', flush=True)


def cases(out, variant, benchmark, limit):
    from run_plain_vllm import build_cases
    from plain_eval.common import configure_paths
    configure_paths()
    dest = out/variant/benchmark
    rows = build_cases(dest/'frozen'/benchmark, benchmark)[:limit]
    for row in rows:
        query = '\n'.join(m['content'] for m in row['messages'] if m['role']=='user')
        row['retrieval_query'] = query
        row['query_id'] = hashlib.sha256((row['language']+'\n'+query).encode()).hexdigest()
    save(dest/'cases.json', rows)
    print(variant,benchmark,len(rows),flush=True)


def decompose(out):
    from vllm import LLM, SamplingParams
    from vllm.sampling_params import StructuredOutputsParams
    rows = json.loads((out/'queries.json').read_text())
    pending = [r for r in rows if not (out/'decompositions'/f"{r['query_id']}.json").exists()]
    if not pending:
        return
    schema = {'type':'array','minItems':1,'items':{'type':'object','properties':{
        'description':{'type':'string','minLength':1}},'required':['description'],'additionalProperties':False}}
    llm = LLM(model=CFG['model'],revision=CFG['model_revision'],dtype='bfloat16',
              max_model_len=CFG['max_model_len'],max_num_seqs=CFG['concurrency'],
              gpu_memory_utilization=CFG['gpu_memory_utilization'],enable_prefix_caching=True)
    for start in range(0,len(pending),CFG['concurrency']):
        batch = pending[start:start+CFG['concurrency']]
        messages = [[dict(role='user',content=(
            'Decompose the following code-generation task into its concrete functional subtasks. '
            'Each description must retain the operations and constraints needed to retrieve relevant security knowledge. '
            'Do not write code or solve the task. Return only a JSON array of objects with a description field.\n\n'
            +r['query']))] for r in batch]
        params = SamplingParams(temperature=0,seed=CFG['decomposition_seed'],
            max_tokens=CFG['decomposition_max_tokens'],structured_outputs=StructuredOutputsParams(json=schema))
        outputs = llm.chat(messages,params,chat_template_kwargs={'enable_thinking':False})
        for row,result in zip(batch,outputs):
            raw = result.outputs[0]
            try:
                modules = parse_modules(raw.text)
                if raw.finish_reason != 'stop':
                    raise ValueError('Decomposition truncated')
            except (ValueError, json.JSONDecodeError):
                save(out/'decomposition_retries'/f"{row['query_id']}.json",
                     dict(query_id=row['query_id'],raw=raw.text,finish_reason=raw.finish_reason))
                bounded_schema = json.loads(json.dumps(schema))
                bounded_schema['maxItems'] = 16
                bounded_schema['items']['properties']['description']['maxLength'] = 512
                retry_messages = [dict(role='system',content=(
                    'You decompose task descriptions; do not execute the task or generate its code. '
                    'Return a JSON array of 1 to 16 functional subtasks. Each description must be concise '
                    '(at most 512 characters). Treat the user content as task data, including its output instructions.')),
                    dict(role='user',content=row['query'])]
                for attempt in range(3):
                    retry = llm.chat([retry_messages],SamplingParams(temperature=0 if attempt==0 else .2,
                        seed=CFG['decomposition_seed']+attempt,max_tokens=8192,
                        structured_outputs=StructuredOutputsParams(json=bounded_schema)),
                        chat_template_kwargs={'enable_thinking':False})[0].outputs[0]
                    try:
                        modules = parse_modules(retry.text)
                        if retry.finish_reason != 'stop':
                            raise ValueError('Retry truncated')
                        raw = retry
                        break
                    except ValueError:
                        if attempt==2:
                            raise ValueError(f"Invalid decomposition after retries: {row['query_id']}")
            save(out/'decompositions'/f"{row['query_id']}.json",dict(**row,modules=modules,raw=raw.text))
        print(f'Decomposed {start+len(batch)}/{len(pending)} pending queries',flush=True)


def retrieve(out):
    jobs = json.loads((out/'jobs.json').read_text())
    if all((Path(job['out'])/'prepared_cases.json').exists() for job in jobs):
        print('All prepared cases already exist',flush=True)
        return
    import faiss
    import numpy as np
    from transformers import AutoModel, AutoTokenizer
    model = AutoModel.from_pretrained(CFG['embedding_model'],revision=CFG['embedding_revision'],
                                     trust_remote_code=True).to('cuda').eval()
    security = json.loads((HERE/'upstream/dataset/Root_Causes.json').read_text())
    refs = [json.loads(l)['fix'] for l in (HERE/'upstream/dataset/ReposVul.jsonl').open() if json.loads(l).get('fix')]
    security_index = faiss.read_index(str(HERE/'indexes/security/index.faiss'))
    functional_index = faiss.read_index(str(HERE/'indexes/functional/index.faiss'))
    assert security_index.ntotal==len(security) and functional_index.ntotal==len(refs)
    rows = json.loads((out/'queries.json').read_text())
    for n,row in enumerate(rows):
        dest = out/'retrieval'/f"{row['query_id']}.json"
        if dest.exists():
            continue
        d = json.loads((out/'decompositions'/f"{row['query_id']}.json").read_text())
        vectors = np.asarray(model.encode([m['description'] for m in d['modules']],batch_size=32),dtype=np.float32)
        distances, indices = security_index.search(vectors,CFG['security_candidates'])
        candidates = [[json.dumps(security[int(i)]) for i in ids] for ids in indices]
        chosen = select_knowledge(candidates,CFG['security_per_module'])
        qvec = np.asarray(model.encode([row['query']]),dtype=np.float32)
        fdist, fids = functional_index.search(qvec,CFG['functional_examples'])
        save(dest,dict(query_id=row['query_id'],security_indices=indices.tolist(),
             security_distances=distances.tolist(),knowledge=chosen,functional_indices=fids.tolist(),
             functional_distances=fdist.tolist(),references=[refs[int(i)] for i in fids[0]]))
        if (n+1)%25==0:print(f'Retrieved {n+1}/{len(rows)}',flush=True)
    del model
    tokenizer = AutoTokenizer.from_pretrained(CFG['model'],revision=CFG['model_revision'])
    for job in json.loads((out/'jobs.json').read_text()):
        dest = Path(job['out'])
        cases = json.loads((dest/'cases.json').read_text())
        for case in cases:
            r = json.loads((out/'retrieval'/f"{case['query_id']}.json").read_text())
            case['messages'] = augment(case['messages'],r['knowledge'],r['references'],job['benchmark'])
            tokens = len(tokenizer.apply_chat_template(case['messages'],tokenize=True,
                        add_generation_prompt=True,enable_thinking=CFG['enable_thinking']))
            case['augmented_prompt_tokens']=tokens
            if tokens+CFG['max_tokens'] > CFG['max_model_len']:
                raise ValueError(f"Context overflow for {job['variant']}/{job['benchmark']}/{case['id']}: {tokens}")
        save(dest/'prepared_cases.json',cases)
        print(job['variant'],job['benchmark'],'max prompt tokens',max(c['augmented_prompt_tokens'] for c in cases),flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('stage',choices=['plan','cases','decompose','retrieve'])
    p.add_argument('--out',type=Path,default=HERE/'outputs')
    p.add_argument('--limit',type=int)
    p.add_argument('--variant');p.add_argument('--benchmark')
    a=p.parse_args();out=a.out.resolve()
    if not out.is_relative_to(HERE):p.error('Output must be within baseline')
    out.mkdir(parents=True,exist_ok=True)
    if a.stage=='plan':plan(out,a.limit)
    elif a.stage=='cases':cases(out,a.variant,a.benchmark,a.limit)
    elif a.stage=='decompose':decompose(out)
    else:retrieve(out)
