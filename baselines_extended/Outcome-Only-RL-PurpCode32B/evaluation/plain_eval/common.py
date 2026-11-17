"""JSON helpers, path setup and prompt builders shared by the plain-vLLM runner."""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f'.{os.getpid()}.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    tmp.replace(path)


def read_json(path):
    return json.loads(Path(path).read_text())


def configure_paths():
    os.environ.setdefault('HF_HOME', '/workspace/hf_home')
    os.environ.setdefault('TOKENIZERS_PARALLELISM', 'false')
    os.environ['VLLM_USE_V2_MODEL_RUNNER'] = '0'
    # BaxBench's prompts module imports agent_cli; a copy is bundled here.
    sys.path.insert(0, str(HERE))
    extra = '/opt/conda/envs/cweval/lib/python3.10/site-packages'
    if Path(extra).is_dir():
        sys.path.append(extra)


def cwe_cases(benchmark):
    sys.path.insert(0, str(benchmark))
    from cweval.ppt import DirectPrompt
    cases = []
    for p in sorted((benchmark / 'benchmark').rglob('*_task.*')):
        if p.suffix[1:] not in ('c', 'cpp', 'py', 'js'):
            continue
        source = p.read_text()
        solution_line = next(l for l in source.splitlines() if 'BEGIN SOLUTION' in l)
        query = source.split('BEGIN PROMPT')[-1].split(solution_line)[0].strip()
        lang = p.suffix[1:]
        prompt = DirectPrompt.PPT.format(lang=lang, lang_instr=DirectPrompt.LANG_INSTR[lang], code_prompt=query)
        cases.append(dict(id=str(p.relative_to(benchmark / 'benchmark')), language=lang,
                          query=query, messages=[dict(role='user', content=prompt)], traces={}))
    assert Counter(c['language'] for c in cases) == dict(c=31, cpp=21, py=25, js=23)
    return cases


def bax_cases(benchmark):
    sys.path.insert(0, str(benchmark / 'src'))
    from env import all_envs
    from scenarios import all_scenarios
    from prompts import _SYSTEM_PROMPT
    return [dict(id=s.id + '/' + e.id, scenario=s.id, framework=e.id,
                 language='py' if e.language.lower() == 'python' else 'js',
                 query='\n'.join((s.short_app_description, s.scenario_instructions, s.api_spec)),
                 messages=[dict(role='system', content=_SYSTEM_PROMPT),
                           dict(role='user', content=s.build_prompt(e, 'openapi', 'none'))], traces={})
            for s in sorted(all_scenarios, key=lambda s:s.id)
            for e in sorted(all_envs, key=lambda e:e.id)
            if e.language.lower() in ('python', 'javascript')]


