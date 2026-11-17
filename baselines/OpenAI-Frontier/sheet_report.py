"""Export verified completed single-sample results for connector publication."""
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
cfg=json.loads((HERE/'configs/campaign.json').read_text())
ready=[];progress=[]
for model in cfg['models']:
    for variant in cfg['variants']:
        for bench,n,columns,metrics in [
            ('seccodeplt',819,[2,5],['functionality@1','security@1','joint@1']),
            ('cweval',100,[6,9],['functionality@1','security@1','joint@1']),
            ('baxbench',224,[10,12],['functionality@1','joint@1'])]:
            root=HERE/'outputs'/model/variant/bench
            p=root/'summary.json'
            progress.append(dict(model=model,variant=variant,benchmark=bench,
                samples=len(list((root/'samples').glob('*.json'))),expected=n,scored=p.exists()))
            if not p.exists():continue
            s=json.loads(p.read_text())
            assert list(s['seeds'])==['42'] and s['seeds']['42']['n']==n and 'sd' not in s
            ready.append(dict(model=model,variant=variant,benchmark=bench,
                row=cfg['sheet_rows'][model][variant],columns=columns,
                values=[round(100*s['mean'][k],2) for k in metrics]))
report=dict(ready=ready,progress=progress)
(HERE/'outputs/sheet_updates.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
