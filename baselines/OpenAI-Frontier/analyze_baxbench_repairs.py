"""Compare Sol gains on repair-affected and genuinely unchanged BaxBench tasks."""
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE/'outputs/gpt-6.1-sol'


def signature(path):
    tree=ast.parse(path.read_text())
    symbols={}
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
            symbols[node.name]=node
        elif isinstance(node,(ast.Assign,ast.AnnAssign)):
            targets=node.targets if isinstance(node,ast.Assign) else [node.target]
            for target in targets:
                for name in ast.walk(target):
                    if isinstance(name,ast.Name):symbols[name.id]=node
        elif isinstance(node,(ast.Import,ast.ImportFrom)):
            for alias in node.names:symbols[alias.asname or alias.name.split('.')[0]]=node
    scenario=next((node for node in ast.walk(tree) if isinstance(node,ast.Call)
        and isinstance(node.func,ast.Name) and node.func.id=='Scenario'),None)
    if scenario is None:return None
    fields={k.arg:k.value for k in scenario.keywords}
    scenario_id=ast.literal_eval(fields['id'])
    # Test lists, their transitive helpers/fixtures, and runtime scenario flags.
    roots={k:v for k,v in fields.items() if k not in
        ['id','short_app_description','api_spec','text_spec','scenario_instructions']}
    pending=[name.id for node in roots.values() for name in ast.walk(node)
             if isinstance(name,ast.Name) and isinstance(name.ctx,ast.Load)]
    dependencies={}
    while pending:
        name=pending.pop()
        if name in dependencies or name not in symbols:continue
        node=symbols[name]
        dependencies[name]=ast.dump(node,include_attributes=False)
        pending.extend(n.id for n in ast.walk(node) if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Load))
    return scenario_id,dict(fields={k:ast.dump(v,include_attributes=False) for k,v in roots.items()},dependencies=dependencies)


def main():
    cases={v:{r['id']:r for r in json.loads((ROOT/v/'baxbench/cases.json').read_text())} for v in ['original','repaired']}
    scores={v:{r['case_id']:r for r in json.loads((ROOT/v/'baxbench/evaluation/scores.json').read_text())} for v in cases}
    samples={v:{r['case_id']:r for r in map(lambda p:json.loads(p.read_text()),(ROOT/v/'baxbench/samples').glob('*.json'))} for v in cases}
    assert all(set(d)==set(cases['original']) for d in [cases['repaired'],*scores.values(),*samples.values()])
    src={v:ROOT/v/'baxbench/frozen/baxbench/src' for v in cases}
    evaluators={v:{} for v in cases}
    for v in cases:
        for file in (src[v]/'scenarios').glob('*.py'):
            result=signature(file)
            if result:evaluators[v][result[0]]=result[1]
    assert set(evaluators['original'])==set(evaluators['repaired'])
    evaluator_changes={s for s in evaluators['original'] if evaluators['original'][s]!=evaluators['repaired'][s]}
    # All shared test helpers, base environment definitions and fixture files match.
    shared=[]
    for subtree in ['env','scenario_files']:
        shared.extend(p.relative_to(src['original']) for p in (src['original']/subtree).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    shared.extend(map(Path,['exploits.py','cwes.py','scenarios/base.py','scenarios/__init__.py']))
    for rel in shared:assert (src['original']/rel).read_bytes()==(src['repaired']/rel).read_bytes(),rel
    # The Parser class used on API final answers is identical. Prompter API changes
    # in the historical benchmark are bypassed by this campaign's job.py.
    parser=[]
    for v in cases:
        tree=ast.parse((src[v]/'prompts.py').read_text())
        parser.append(ast.dump(next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Parser'),include_attributes=False))
    assert parser[0]==parser[1]
    records=[]
    for key in cases['original']:
        prompt=cases['original'][key]['messages']!=cases['repaired'][key]['messages']
        evaluator=key.split('/')[0] in evaluator_changes
        cohort='both' if prompt and evaluator else 'prompt_only' if prompt else 'evaluator_only' if evaluator else 'neither'
        same_request=samples['original'][key]['request_sha256']==samples['repaired'][key]['request_sha256']
        if not prompt:assert same_request,key
        records.append(dict(case_id=key,scenario=key.split('/')[0],prompt_changed=prompt,evaluator_changed=evaluator,
            cohort=cohort,request_identical=same_request,original={m:scores['original'][key][m] for m in ['functionality','security','joint']},
            repaired={m:scores['repaired'][key][m] for m in ['functionality','security','joint']}))
    groups={}
    for label in ['any_repair','neither','prompt_only','evaluator_only','both']:
        rows=[r for r in records if r['cohort']!='neither'] if label=='any_repair' else [r for r in records if r['cohort']==label]
        stats={}
        for m in ['functionality','security','joint']:
            before=sum(r['original'][m] for r in rows);after=sum(r['repaired'][m] for r in rows)
            stats[m]=dict(original_passes=before,repaired_passes=after,original_percent=100*before/len(rows),
                repaired_percent=100*after/len(rows),delta_pp=100*(after-before)/len(rows),
                gained=sum(not r['original'][m] and r['repaired'][m] for r in rows),
                lost=sum(r['original'][m] and not r['repaired'][m] for r in rows))
        groups[label]=dict(tasks=len(rows),metrics=stats)
    report=dict(model='gpt-6.1-sol',reasoning_effort='high',repetitions=1,groups=groups,
        evaluator_changed_scenarios=sorted(evaluator_changes),records=records,
        returned_models={v:dict(Counter(r.get('returned_model') for r in samples[v].values())) for v in samples},
        unchanged_shared_files=len(shared),parser_identical=True,
        shared_runtime_audit='tasks.py changes are port acquisition (overridden identically by baseline repair_ports) and num_findings/aggregate reporting. Our task-level scores consume num_passed_ft, num_total_ft, cwes and exception counts; their semantics are unchanged.',
        interpretation='Fresh API samples, no fixed API seed. Unchanged-cohort improvement prevents attributing the entire aggregate improvement to repairs alone.')
    out=HERE/'outputs/analysis';out.mkdir(exist_ok=True)
    (out/'baxbench_repair_cohorts.json').write_text(json.dumps(report,indent=2)+'\n')
    lines=['# Sol BaxBench: combined repair effect vs untouched control','',
        '| Cohort | Tasks | Original joint | Repaired joint | Delta (pp) | Gained / lost |',
        '| --- | ---: | ---: | ---: | ---: | ---: |']
    for name,g in groups.items():
        s=g['metrics']['joint'];lines.append(f"| {name} | {g['tasks']} | {s['original_passes']} ({s['original_percent']:.2f}%) | {s['repaired_passes']} ({s['repaired_percent']:.2f}%) | {s['delta_pp']:+.2f} | {s['gained']} / {s['lost']} |")
    lines+=['','Evaluator changes: '+', '.join(sorted(evaluator_changes))+'.',
        '',report['shared_runtime_audit'],'',report['interpretation']]
    (out/'baxbench_repair_cohorts.md').write_text('\n'.join(lines)+'\n')
    print('\n'.join(lines))
    print('Returned models',report['returned_models'])


if __name__=='__main__':main()
