"""Our retrieval (same-language top-3, rendered as in our experiments) for the tasks outside
Python/C/C++/JavaScript: CWEval Go and BaxBench Go/PHP/Ruby/Rust. The knowledge base has no records in these languages, so they retrieve
from the Python records (for BaxBench, the Python web-framework tasks). Writes outputs_extra/repaired/<bench>/prepared_cases.json."""
import ast, json, os, pickle, subprocess, sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

HERE = Path(__file__).resolve().parent
CFG = json.loads((HERE / 'configs/campaign.json').read_text())
os.environ['HF_HOME'] = CFG['hf_home']; os.environ['CUDA_DEVICE_ORDER'] = 'PCI_BUS_ID'
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE / 'evaluation'))
INTRO = 'Here are retrieved samples that may help implement the task securely'
node = next(n for n in ast.parse((HERE / 'upstream/knowledge_retrieval.py').read_text()).body
            if isinstance(n, ast.FunctionDef) and n.name == 'format_security_context')
ns = {'Any': Any, 'json': json}; exec(compile(ast.Module(body=[node], type_ignores=[]), 'x', 'exec'), ns); render = ns['format_security_context']

import faiss, numpy as np  # noqa: E402
from transformers import AutoModel, AutoTokenizer  # noqa: E402
from run_plain_vllm import freeze_sources  # noqa: E402

out = HERE / 'outputs_extra/repaired'
kb = [json.loads(l) for l in (HERE / 'dataset/all_languages.jsonl').read_text().splitlines() if l.strip()]
keys = json.loads((HERE / 'dataset/retrieval_keys.json').read_text())
for r in kb: r['retrieval_key'] = keys[r['cwe'].upper()]['retrieval_key']   # CWE-level guideline shown with each record
byid = {r['attempt_key']: r for r in kb}
directory = HERE / 'indexes/python'
index = faiss.read_index(str(directory / 'index.faiss'))
with (directory / 'index.pkl').open('rb') as f: ds, mapping = pickle.load(f)
records = [byid[json.loads(ds.search(mapping[i]).page_content)['attempt_key']] for i in range(index.ntotal)]
assert all(r['language'] == 'python' for r in records)
model = AutoModel.from_pretrained(CFG['embedding_model'], revision=CFG['embedding_revision'], trust_remote_code=True).to('cuda').eval()
tok = AutoTokenizer.from_pretrained(CFG['model'], revision=CFG['model_revision'])
for bench in ('cweval', 'baxbench'):
    dest = out / bench; dest.mkdir(parents=True, exist_ok=True)
    frozen = freeze_sources(SimpleNamespace(out=dest, benchmark=bench, variant='repaired', benchmarks_root=HERE.parents[1] / 'benchmarks'))
    subprocess.run(['/opt/conda/envs/vllm/bin/python', '-c',
        'import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
        'from plain_eval.common import configure_paths;configure_paths();from plain_eval.extra import build_extra_cases;'
        'Path(sys.argv[4]).write_text(json.dumps(build_extra_cases(Path(sys.argv[2]),sys.argv[3])))',
        str(HERE / 'evaluation'), str(frozen), bench, str(dest / 'base_cases.json')], check=True)
    cases = json.loads((dest / 'base_cases.json').read_text())
    for case in cases:
        hits = []
        vec = np.asarray(model.encode([case['query']]), dtype=np.float32)
        dist, ids = index.search(vec, 3)
        hits = [dict(rank=i + 1, score=float(d), record=records[int(j)]) for i, (d, j) in enumerate(zip(dist[0], ids[0]))]
        context = '\n\n'.join(render(h['record'], allow_empty_snippets=True) for h in hits)
        case['messages'] = [dict(m) for m in case['messages']]
        assert case['messages'][-1]['role'] == 'user'
        case['messages'][-1]['content'] += '\n\n' + INTRO + '\n\n' + context + '\n\n'
        case.update(retrieval=hits, context=context, retrieval_query=case['query'], retrieval_language='python')
        case['prompt_tokens'] = len(tok.apply_chat_template(case['messages'], tokenize=True, add_generation_prompt=True, enable_thinking=True))
        assert case['prompt_tokens'] + CFG['max_tokens'] <= CFG['max_model_len'], case['id']
    (dest / 'prepared_cases.json').write_text(json.dumps(cases, indent=2, ensure_ascii=False) + '\n')
    print(bench, len(cases), 'prepared; max prompt tokens', max(c['prompt_tokens'] for c in cases), flush=True)
