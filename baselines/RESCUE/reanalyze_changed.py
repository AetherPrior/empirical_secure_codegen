"""Redo the RESCUE vulnerability-cause analysis for the SecCodePLT tasks whose prompt changed, in place in
outputs/seccodeplt/analysis.json (same prompt and sampling as prepare.py analyze). Then run
`prepare.py retrieve --sets seccodeplt` to rebuild the prepared cases."""
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / 'benchmarks'))
from regen_changed_tasks import CHANGED  # noqa: E402

os.environ.update(VLLM_USE_FLASHINFER_SAMPLER='0', VLLM_USE_DEEP_GEMM='0', TOKENIZERS_PARALLELISM='false',
                  HF_HOME='/workspace/hf_home')
from vllm import LLM, SamplingParams  # noqa: E402

prompt_t = re.search(r'analyze_vuln_cause_prompt = """\n(.*?)\n""".strip\(\)',
                     (REPO / 'RESCUE/src/rescue/retrieval/hmr.py').read_text(), re.S).group(1)
cases = [c for c in json.loads((REPO / 'baselines/CodeGuarder/outputs/repaired/seccodeplt/cases.json').read_text())
         if c['id'] in CHANGED]
assert len(cases) == len(CHANGED)
llm = LLM('Qwen/Qwen3-8B', dtype='bfloat16', max_model_len=24576, gpu_memory_utilization=0.9, seed=42)
tok = llm.get_tokenizer()
user_text = lambda c: '\n'.join(m['content'] for m in c['messages'] if m['role'] == 'user')
prompts = [tok.apply_chat_template([dict(role='user', content=prompt_t.replace('{lang}', 'python').replace('{code}', user_text(c)))],
                                   tokenize=False, add_generation_prompt=True, enable_thinking=False) for c in cases]
outs = llm.generate(prompts, SamplingParams(temperature=0.6, top_p=0.95, max_tokens=1024, seed=42))
path = HERE / 'outputs/seccodeplt/analysis.json'
analysis = json.loads(path.read_text())
for c, o in zip(cases, outs):
    analysis[c['id']] = o.outputs[0].text
path.write_text(json.dumps(analysis, indent=1))
print('reanalyzed', len(cases), flush=True)
