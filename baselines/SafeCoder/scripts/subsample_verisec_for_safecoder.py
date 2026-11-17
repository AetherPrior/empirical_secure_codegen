#!/usr/bin/env python3
"""Stratified subsample of the VeriSec pairs used for SafeCoder, sized so that the security share of an epoch matches SafeCoder's own recipe.
SafeCoder's own security files (sec-desc + sec-new-desc) give 1,141 train pairs -> 1,928 samples (2,539 after its minority upsampling to 20 per cwe x language)
against 30,087 utility samples (evol), i.e. a security share of 7.8% per epoch. Taking all 8,469 VeriSec pairs would raise it to ~35%.
Strata are language x CWE (80); allocation is proportional with at least one pair per stratum (every CWE and language stays represented), largest-remainder rounding,
deterministic (seed 42). Validation pairs are left as they are."""
import json, random, sys
from collections import defaultdict
src, n_target, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
rows = [json.loads(l) for l in open(src)]
strata = defaultdict(list)
for r in rows: strata[(r['file_name'].rsplit('.', 1)[1], r['vul_type'])].append(r)
keys = sorted(strata)
assert n_target >= len(keys)
quota = {k: 1 for k in keys}; left = n_target - len(keys)
want = {k: (len(strata[k]) - 1) / sum(len(strata[j]) - 1 for j in keys) * left for k in keys}
for k in keys: quota[k] += int(want[k])
rest = n_target - sum(quota.values())
for k in sorted(keys, key=lambda k: want[k] - int(want[k]), reverse=True)[:rest]: quota[k] += 1
rng = random.Random(42); picked = []
for k in keys:
    s = list(strata[k]); rng.shuffle(s); picked += s[:min(quota[k], len(s))]
rng.shuffle(picked)
open(out, 'w').write(''.join(json.dumps(x) + '\n' for x in picked))
lang = defaultdict(int)
for r in picked: lang[r['file_name'].rsplit('.', 1)[1]] += 1
print(len(picked), 'pairs;', len(keys), 'strata;', len({r['vul_type'] for r in picked}), 'cwes;', dict(lang))
