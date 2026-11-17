"""Failure-pattern table for one seed (the paper uses seed 42), from the saved judge labels (no judge calls).

Writes seed<SEED>_table.json (or seed<SEED>_table_rel.json with --related) next to this script:
  table                     per "bench/method": number of failures n, the share of each pattern in percent, raw counts
  ret_sec_failures          our retrieval on SecCodePLT: functional-but-insecure generations
  ret_sec_failures_on_miss  ... of which none of the three retrieved records has the task's CWE
  ret_never                 our retrieval on SecCodePLT: failures labeled never_raised
  ret_never_on_miss         ... of which the retrieval missed the task's CWE
  ret_never_cwe             CWE counts of those never_raised retrieval misses

A retrieved record "has the task's CWE" when its CWE equals the task's CWE; with --related, a one-hop related CWE in
MITRE's CWE list (cwe_rel.py) also counts.

usage: python seed_table.py [--seed 42] [--related] [--root <repository root>]
"""
import argparse
import collections
import json
import re
from pathlib import Path

import cwe_rel

HERE = Path(__file__).resolve().parent
RETRIEVAL_RUN = "baselines_extended/Our-Retrieval/outputs/repaired/seccodeplt"


def pattern_table(labels):
    counts = collections.defaultdict(collections.Counter)
    for label in labels:
        counts[(label["bench"], label["method"])][label["category"]] += 1
    table = {}
    for (bench, method), patterns in sorted(counts.items()):
        n = sum(patterns.values())
        table[f"{bench}/{method}"] = {"n": n, **{p: round(100 * patterns[p] / n) for p in patterns}, "raw": dict(patterns)}
    return table


def retrieved_cwes(context):
    """CWEs of the retrieved records, read from the rendered retrieval context."""
    return re.findall(r"^CWE: CWE-(\d+)", context, re.M)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--related", action="store_true", help="count one-hop related CWEs as a match")
    parser.add_argument("--root", type=Path, default=HERE.parents[1], help="repository root (default: this artifact)")
    args = parser.parse_args()
    root = args.root.resolve()

    labels = [label for label in json.load(open(HERE / "judge_v2.json")) if label["seed"] == args.seed]
    out = {"seed": args.seed, "table": pattern_table(labels)}

    # Did our retrieval return a record of the task's CWE? (SecCodePLT)
    tasks = {json.loads(line)["id"]: json.loads(line)
             for line in open(root / "benchmarks/secode-eval_repaired/data/insecure_coding.jsonl")}
    run = root / RETRIEVAL_RUN
    cases = {case["id"]: case for case in json.load(open(run / "prepared_cases.json"))}
    has_cwe = {}
    for task_id, case in cases.items():
        cwes = retrieved_cwes(case["context"])
        task_cwe = tasks[task_id]["CWE_ID"]
        has_cwe[task_id] = cwe_rel.matches(task_cwe, cwes) if args.related else str(task_cwe) in cwes

    scores = [row for row in json.load(open(run / "oracle_fuzzed.json"))["rows"] if row["seed"] == args.seed]
    insecure = [row for row in scores if row["functionality"] and not row["security"]]
    out["ret_sec_failures"] = len(insecure)
    out["ret_sec_failures_on_miss"] = sum(not has_cwe[row["case_id"]] for row in insecure)

    never = [label for label in labels
             if label["bench"] == "seccodeplt" and label["method"] == "Retrieval" and label["category"] == "never_raised"]
    out["ret_never"] = len(never)
    out["ret_never_on_miss"] = sum(not has_cwe[label["case"]] for label in never)
    out["ret_never_cwe"] = dict(collections.Counter(label["cwe"] for label in never if not has_cwe[label["case"]]))

    name = f"seed{args.seed}_table" + ("_rel" if args.related else "") + ".json"
    json.dump(out, open(HERE / name, "w"), indent=1)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
