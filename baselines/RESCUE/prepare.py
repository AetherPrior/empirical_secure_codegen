"""RESCUE (ICLR 2026) on the plain Qwen3-8B protocol: draft -> vulnerability-cause analysis -> hierarchical multi-faceted retrieval -> knowledge-augmented prompt.

Stages (see run.sh):
  analyze   (vllm env, 1 GPU)  Qwen3-8B (thinking off) writes the upstream vulnerability-cause paragraph for every task.
  retrieve  (RESCUE .venv, CPU) upstream HMR (BGE dense + BM25 over API calls, RRF, CWE level then code level) -> prepared_cases.json
The draft is the model's own plain thinking-mode answer (seed 42) already produced for the base-model row, as upstream's draft is the model's zero-shot code.
Upstream index selection is kept: the Python knowledge base serves Python, JavaScript, Go, PHP, Ruby, Rust; the C knowledge base serves C and C++.
"""
import argparse, json, os, re, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RESCUE = HERE / 'upstream'   # upstream RESCUE code and knowledge base
OUT = HERE / 'outputs'
GEN = REPO / 'baselines/Qwen3-8B-base/outputs/repaired'
EXTRA = REPO / 'baselines_extended/extra_runs/qwen3-8b'
# set name -> (base cases, draft generations)
SETS = {}
for b in ('seccodeplt', 'cweval', 'baxbench'):
    SETS[b] = (REPO / f'baselines/CodeGuarder/outputs/repaired/{b}/cases.json', GEN / b / 'generations.jsonl')
for b in ('cweval', 'baxbench'):
    SETS[f'extra_{b}'] = (REPO / f'baselines_extended/Our-Retrieval/outputs_extra/repaired/{b}/base_cases.json', EXTRA / f'extra_{b}/generations.jsonl')
SHORT = dict(python='py', c='c', cpp='cpp', javascript='js', go='go', php='php', ruby='rb', rust='rust')
FULL = dict(py='python', c='c', cpp='cpp', js='javascript', go='go', php='php', rb='ruby', rust='rust')


def user_text(case):
    return '\n'.join(m['content'] for m in case['messages'] if m['role'] == 'user')


def analyze(sets):
    sys.path.insert(0, str(RESCUE))
    os.environ.update(VLLM_USE_FLASHINFER_SAMPLER='0', VLLM_USE_DEEP_GEMM='0', TOKENIZERS_PARALLELISM='false', HF_HOME='/workspace/hf_home')
    from vllm import LLM, SamplingParams
    prompt_t = re.search(r'analyze_vuln_cause_prompt = """\n(.*?)\n""".strip\(\)', (RESCUE / 'src/rescue/retrieval/hmr.py').read_text(), re.S).group(1)
    llm = LLM('Qwen/Qwen3-8B', dtype='bfloat16', max_model_len=24576, gpu_memory_utilization=0.9, seed=42)
    tok = llm.get_tokenizer()
    sp = SamplingParams(temperature=0.6, top_p=0.95, max_tokens=1024, seed=42)
    for name in sets:
        dest = OUT / name; dest.mkdir(parents=True, exist_ok=True)
        path = dest / 'analysis.json'
        if path.exists(): continue
        cases = json.loads(SETS[name][0].read_text())
        prompts = []
        for c in cases:
            # upstream fills {lang} with the full language name and {code} with the task's code snippet; here the code snippet is the task prompt
            text = prompt_t.replace('{lang}', FULL.get(SHORT.get(c['language'], c['language']), c['language'])).replace('{code}', user_text(c))
            prompts.append(tok.apply_chat_template([dict(role='user', content=text)], tokenize=False, add_generation_prompt=True, enable_thinking=False))
        outs = llm.generate(prompts, sp)
        path.write_text(json.dumps({c['id']: o.outputs[0].text for c, o in zip(cases, outs)}, indent=1))
        print(name, len(cases), 'analyzed', flush=True)


def draft_code(answer, benchmark):
    if benchmark.endswith('baxbench'):
        return answer.strip()
    blocks = re.findall(r'```[^\n]*\n(.*?)```', answer, re.S)
    return blocks[-1].strip() if blocks else answer.strip()


def retrieve(sets, limit):
    sys.setrecursionlimit(20000)
    os.chdir(RESCUE); sys.path.insert(0, str(RESCUE))
    os.environ.setdefault('CUDA_VISIBLE_DEVICES', '3')   # the encoder runs on one GPU, as upstream (cuda:0, fp16)
    from src.rescue.retrieval import hmr
    from src.rescue.construction import api_extraction
    from FlagEmbedding import FlagModel
    Misc, Retrieve, Load = hmr.Misc, hmr.Retrieve, hmr.Load
    enc = FlagModel('BAAI/bge-base-en-v1.5', use_fp16=True, devices=['cuda:0'])
    hmr._ENCODER = enc
    loader, retriever = Load(), Retrieve()
    template = hmr.knowledge_prompt_template
    for name in sets:
        base = json.loads(SETS[name][0].read_text())[:limit]
        analysis = json.loads((OUT / name / 'analysis.json').read_text())
        drafts = {}
        for line in SETS[name][1].read_text().splitlines():
            r = json.loads(line)
            if r['seed'] == 42 and r['status'] == 'completed': drafts[r['case_id']] = r['answer']
        prepared, stats = [], dict(n=0, no_draft=0, empty=0)
        for c in base:
            stats['n'] += 1
            short = SHORT.get(c['language'], c['language'])
            language = Misc.from_short_to_full_language(short)
            draft = draft_code(drafts.get(c['id'], ''), name)
            stats['no_draft'] += not draft
            vuln = Misc.extract_vuln_analysis_result(analysis[c['id']])
            enc_ = loader.dense_encoder()
            cwe_vuln_idx = loader.cwe_level_vuln_text_dense_index(enc_)[language]
            cwe_api_idx = loader.cwe_level_api_bm25_index()[language]
            try: calls = api_extraction.extract_method_calls(language, draft)
            except RecursionError:   # a degenerate, deeply nested draft overflows upstream's recursive tree walk; treat as no API calls
                stats['recursion'] = stats.get('recursion', 0) + 1; calls = []
            cwe_scores = Misc.rrf_variant_top_n_with_threshold(cwe_api_idx.get_scores(calls), retriever.dense(vuln, enc_, cwe_vuln_idx), thresholds=[4.0, 0.75])
            cwe_sel = Misc.top_k(cwe_scores, 4, 0)
            filt = Misc.get_code_level_selected_indices_by_cwe_types(cwe_sel, language)
            ck = loader.load_cwe_level_and_code_level_knowledge()
            code_kb, cwe_kb = ck[0][language], ck[1][language]
            knowledge = ''
            if len(filt):
                api_s = loader.api_bm25_index()[language].get_scores(calls)[filt]
                vuln_s = retriever.dense(vuln, enc_, loader.vuln_text_dense_index(enc_)[language])[filt]
                code_s = retriever.dense(draft, enc_, loader.sliced_code_dense_index(enc_)[language])[filt]
                top = Misc.top_k(Misc.rrf_variant_top_n_with_threshold(api_s, vuln_s, code_s, thresholds=[4.0, 0.75, 0.65]), 1, 0)
                if len(top):
                    entry = code_kb[filt[top[0]]]
                    key = ('c' if short in ('c', 'cpp') else 'py') + '-' + entry['cwe'].lower()
                    knowledge = template.format(security_guidelines=cwe_kb[key]['security_guidelines'], language=language, secure_code=entry['sec_sliced_code'])
            row = dict(c)
            row['rescue'] = dict(knowledge=knowledge, vuln_cause=vuln, draft_chars=len(draft), index='c' if short in ('c', 'cpp') else 'python')
            if knowledge:
                msgs = [dict(m) for m in c['messages']]
                i = max(i for i, m in enumerate(msgs) if m['role'] == 'user')
                msgs[i]['content'] = ('Given the following security knowledge:\n<security document>\n' + knowledge + '\n</security document>\n\n'
                    + msgs[i]['content'] + '\n\nYou can refer to the provided security knowledge but do not simply copy and paste it. First think how it works and whether it applies to this task.')
                row['messages'] = msgs
            else:
                stats['empty'] += 1
            prepared.append(row)
        (OUT / name / 'prepared_cases.json').write_text(json.dumps(prepared, indent=1))
        print(name, stats, flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('stage', choices=['analyze', 'retrieve']); p.add_argument('--sets', nargs='*', default=list(SETS)); p.add_argument('--limit', type=int, default=None)
    a = p.parse_args()
    (analyze if a.stage == 'analyze' else lambda s: retrieve(s, a.limit))(a.sets)
