"""Dump the benchmark prompts (same builders as benchmarks/run_plain_vllm.py) so the HF-based SVEN generator needs no benchmark dependencies.
Run with the vllm environment. Usage: sven_dump_cases.py <benchmark> <out dir> [--extra]"""
import argparse, json, sys
from pathlib import Path
from types import SimpleNamespace
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / 'benchmarks'))
import run_plain_vllm as R  # noqa: E402
from plain_eval.common import configure_paths  # noqa: E402
p = argparse.ArgumentParser(); p.add_argument('benchmark'); p.add_argument('out', type=Path); p.add_argument('--extra', action='store_true')
a = p.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
configure_paths()
frozen = R.freeze_sources(SimpleNamespace(out=a.out.resolve(), benchmark=a.benchmark, variant='repaired', benchmarks_root=REPO / 'benchmarks'))
if a.extra:
    from plain_eval.extra import build_extra_cases
    cases = build_extra_cases(frozen, a.benchmark)
else:
    cases = R.build_cases(frozen, a.benchmark)
(a.out / 'cases.json').write_text(json.dumps([dict(id=c['id'], messages=c['messages']) for c in cases]))
print(a.benchmark, 'extra' if a.extra else 'main', len(cases), 'cases')
