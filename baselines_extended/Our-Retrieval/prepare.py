"""Strict same-language functionality top-3 retrieval, rendered as in our experiments."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any

HERE=Path(__file__).resolve().parent
CFG=json.loads((HERE/'configs/campaign.json').read_text())
os.environ['HF_HOME']=CFG['hf_home']
sys.dont_write_bytecode=True
sys.path.insert(0,str(HERE/'evaluation'))
INTRO='Here are retrieved samples that may help implement the task securely'

source=HERE/'upstream/knowledge_retrieval.py'
node=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='format_security_context')
ns={'Any':Any,'json':json}
exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),ns)
render=ns['format_security_context']


def save(path,value):
    tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n');tmp.replace(path)


def main():
    p=argparse.ArgumentParser();p.add_argument('--variant',required=True,choices=['original','repaired']);p.add_argument('--gpu',required=True,choices=['2','3'])
    a=p.parse_args();os.environ['CUDA_VISIBLE_DEVICES']=a.gpu
    os.environ['CUDA_DEVICE_ORDER']='PCI_BUS_ID'
    import faiss
    import numpy as np
    import pickle
    from transformers import AutoModel,AutoTokenizer
    from run_plain_vllm import freeze_sources,build_cases
    from plain_eval.common import configure_paths
    configure_paths()
    out=HERE/os.environ.get('RETRIEVAL_OUT_ROOT','outputs')/a.variant
    raw=(HERE/'dataset/all_languages.jsonl').read_bytes()
    kb=[json.loads(line) for line in raw.decode().splitlines() if line.strip()]
    keys=json.loads((HERE/'dataset/retrieval_keys.json').read_text())
    for r in kb:r['retrieval_key']=keys[r['cwe'].upper()]['retrieval_key']   # CWE-level guideline shown with each record
    byid={r['attempt_key']:r for r in kb};assert len(byid)==len(kb)
    indexes={};records={}
    for lang in ['c','cpp','python','javascript']:
        directory=HERE/'indexes'/lang
        indexes[lang]=faiss.read_index(str(directory/'index.faiss'))
        with (directory/'index.pkl').open('rb') as f:ds,mapping=pickle.load(f)
        records[lang]=[]
        for i in range(indexes[lang].ntotal):
            historic=json.loads(ds.search(mapping[i]).page_content)
            row=byid[historic['attempt_key']]
            if row['language']!=lang or row['extraction']['functionality']!=historic['extraction']['functionality']:
                raise ValueError('Index language/functionality mismatch')
            records[lang].append(row)
        assert len(records[lang])==sum(r['language']==lang for r in kb)
    model=None;tokenizer=None
    cache={}
    for bench in CFG['benchmarks']:
        dest=out/bench;dest.mkdir(parents=True,exist_ok=True)
        args=SimpleNamespace(out=dest,benchmark=bench,variant=a.variant,benchmarks_root=HERE.parents[1]/'benchmarks')
        frozen=freeze_sources(args)
        if (dest/'prepared_cases.json').exists():continue
        # Benchmark prompt imports require the evaluator environment's native
        # dependencies; keep them out of the separate Jina environment.
        import subprocess
        subprocess.run(['/opt/conda/envs/vllm/bin/python','-c',
            'import sys,json;from pathlib import Path;'
            'sys.path.insert(0,sys.argv[1]);'
            'from run_plain_vllm import build_cases;'
            'from plain_eval.common import configure_paths;configure_paths();'
            'Path(sys.argv[4]).write_text(json.dumps(build_cases(Path(sys.argv[2]),sys.argv[3])))',
            str(HERE/'evaluation'),str(frozen),bench,str(dest/'base_cases.json')],check=True)
        cases=json.loads((dest/'base_cases.json').read_text())
        if model is None:
            model=AutoModel.from_pretrained(CFG['embedding_model'],revision=CFG['embedding_revision'],trust_remote_code=True).to('cuda').eval()
            tokenizer=AutoTokenizer.from_pretrained(CFG['model'],revision=CFG['model_revision'])
        descriptions={}
        if bench=='seccodeplt':
            descriptions={str(r['id']):r['task_description']['description'] for r in
                (json.loads(l) for l in (frozen/'data/insecure_coding.jsonl').open() if l.strip())}
        for n,case in enumerate(cases):
            lang={'py':'python','js':'javascript'}.get(case['language'],case['language'])
            query=case.get('query') or descriptions[case['id']]
            key=(lang,query)
            if key not in cache:
                vectors=np.asarray(model.encode([query]),dtype=np.float32)
                distances,ids=indexes[lang].search(vectors,3)
                cache[key]=[dict(rank=i+1,score=float(d),record=records[lang][int(j)])
                    for i,(d,j) in enumerate(zip(distances[0],ids[0]))]
            hits=cache[key]
            context='\n\n'.join(render(h['record'],allow_empty_snippets=True) for h in hits)
            case['messages']=[dict(m) for m in case['messages']]
            assert case['messages'][-1]['role']=='user'
            case['messages'][-1]['content']+='\n\n'+INTRO+'\n\n'+context+'\n\n'
            case.update(retrieval=hits,context=context,retrieval_query=query)
            tokens=len(tokenizer.apply_chat_template(case['messages'],tokenize=True,add_generation_prompt=True,enable_thinking=True))
            case['prompt_tokens']=tokens
            if tokens+CFG['max_tokens']>CFG['max_model_len']:
                raise ValueError(f'Context overflow: {a.variant}/{bench}/{case["id"]}')
            if (n+1)%50==0:print(a.variant,bench,n+1,'retrieved',flush=True)
        save(dest/'prepared_cases.json',cases)
        save(dest/'retrieval_provenance.json',dict(kb_sha256=hashlib.sha256(raw).hexdigest(),rows=len(kb),
            placement='user',top_k=3,strict_language_routing=True,wait_forcing=False,
            model=CFG['embedding_model'],revision=CFG['embedding_revision'],max_prompt_tokens=max(c['prompt_tokens'] for c in cases)))
        print(a.variant,bench,len(cases),'prepared',flush=True)


if __name__=='__main__':main()
