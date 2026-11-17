"""Tasks outside the Python/C/C++/JavaScript slice (CWEval Go, BaxBench Go/PHP/Ruby/Rust); same prompts as common.py."""


def build_extra_cases(bench, benchmark):
    """Cases outside the Python/C/C++/JavaScript slice of benchmarks/plain_eval/common.py: CWEval Go tasks and the
    BaxBench frameworks that are not Python or JavaScript. Prompts are built exactly as in common.py."""
    import sys as _sys
    if benchmark == 'cweval':
        _sys.path.insert(0, str(bench))
        from cweval.ppt import DirectPrompt
        cases = []
        for p in sorted((bench / 'benchmark').rglob('*_task.go')):
            source = p.read_text()
            solution_line = next(l for l in source.splitlines() if 'BEGIN SOLUTION' in l)
            query = source.split('BEGIN PROMPT')[-1].split(solution_line)[0].strip()
            prompt = DirectPrompt.PPT.format(lang='go', lang_instr=DirectPrompt.LANG_INSTR['go'], code_prompt=query)
            cases.append(dict(id=str(p.relative_to(bench / 'benchmark')), language='go', query=query,
                              messages=[dict(role='user', content=prompt)], traces={}))
        return cases
    _sys.path.insert(0, str(bench / 'src'))
    from env import all_envs
    from scenarios import all_scenarios
    from prompts import _SYSTEM_PROMPT
    return [dict(id=s.id + '/' + e.id, scenario=s.id, framework=e.id, language=e.language.lower(),
                 query='\n'.join((s.short_app_description, s.scenario_instructions, s.api_spec)),
                 messages=[dict(role='system', content=_SYSTEM_PROMPT),
                           dict(role='user', content=s.build_prompt(e, 'openapi', 'none'))], traces={})
            for s in sorted(all_scenarios, key=lambda s: s.id)
            for e in sorted(all_envs, key=lambda e: e.id)
            if e.language.lower() not in ('python', 'javascript')]
