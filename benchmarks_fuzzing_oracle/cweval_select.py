"""Choose CWEval fuzz tests with the per-CWE checks (same rule as SecCodePLT: secure reference fine, a vulnerable
reference violates). usage: cweval_select.py --out <tests dir> [--jobs 32]"""
import argparse, json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import select_and_score as S

TASKS = S.REPO / "benchmarks_fuzzing" / "tasks" / "cweval"

def main():
    p = argparse.ArgumentParser(); p.add_argument("--out", type=Path, required=True); p.add_argument("--jobs", type=int, default=32)
    a = p.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    def one(d):
        tests = S.select_tests(d)
        (a.out / f"{d.name}.json").write_text(json.dumps(tests, indent=1))
        m = json.loads((d / "meta.json").read_text())
        return d.name, m["cwe"], m.get("lang", "py"), len(tests)
    with ThreadPoolExecutor(a.jobs) as pool:
        rows = list(pool.map(one, sorted(TASKS.iterdir())))
    for r in rows: print(*r)
    print("pairs with tests:", sum(1 for r in rows if r[3]), "tests:", sum(r[3] for r in rows))

main()
