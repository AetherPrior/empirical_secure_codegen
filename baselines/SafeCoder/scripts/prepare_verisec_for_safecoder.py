#!/usr/bin/env python3
"""Convert VeriSec pairwise (secure/vulnerable pairs, four languages) into SafeCoder's security-training JSONL.
Fields follow sec-new-desc: description (task prompt), func_src_before (vulnerable), func_src_after (secure),
file_name (extension gives the language), vul_type (cwe-N). 10% of the pairs, stratified by language, go to val (SafeCoder's own val files are about 10% of each dataset); the rest are train."""
import json, random, sys
from collections import defaultdict
src, outdir = sys.argv[1], sys.argv[2]
EXT = dict(python='py', c='c', cpp='cpp', javascript='js')
rows = [json.loads(l) for l in open(src)]
by = defaultdict(list)
for i, r in enumerate(rows): by[r['language']].append(i)
rng = random.Random(42); val = set()
for L, idx in by.items():
    rng.shuffle(idx); val.update(idx[:max(1, round(0.10 * len(idx)))])
tr, va = [], []
for i, r in enumerate(rows):
    cwe = r['cwe'].lower()
    j = dict(func_name='(task)', func_src_before=r['vulnerable_code'], func_src_after=r['secure_code'], line_changes='{}', char_changes='{}',
             commit_link='None', file_name=f"{cwe}_{i:06d}.{EXT[r['language']]}", vul_type=cwe, commit_msg='verisec execution-filtered pair',
             parent_commit='None', description=r['prompt'], source='verisec-pairwise', task_id=r['task_id'])
    (va if i in val else tr).append(j)
for name, d in (('train', tr), ('val', va)):
    open(f'{outdir}/{name}/sec-verisec.jsonl', 'w').write(''.join(json.dumps(x) + '\n' for x in d))
print(len(tr), 'train', len(va), 'val')
