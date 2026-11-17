#!/usr/bin/env python3
"""Score audit JSONL vs Resolve labels from compare CSV.

Bucket semantics (auditor catching invalid rows):
  Resolve N = invalid (should be caught)
  Resolve Y = valid (should stay UNCHANGED)
  TP = N and change in (reject, rewrite)
  TN = Y and change == UNCHANGED
  FN = N and change == UNCHANGED  (missed invalid)
  FP = Y and change == reject     (wrongly dropped valid)
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def load_resolve(compare_csv: Path, cwe: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with compare_csv.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row["cwe"] == cwe:
                out[row["function_name"]] = row["Resolve"]
    return out


def score_audit(audit_path: Path, resolve: dict[str, str]) -> dict:
    audits = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
    tp = tn = fp = fn = 0
    rows: list[tuple[str, str, str, str]] = []
    counts = {"reject": 0, "rewrite": 0, "UNCHANGED": 0}
    for a in audits:
        name = a["row_key"].split("|")[-1]
        gt = resolve[name]
        ch = a.get("change", "")
        counts[ch] = counts.get(ch, 0) + 1
        invalid = gt == "N"
        if invalid and ch in ("reject", "rewrite"):
            tp += 1
            tag = "TP"
        elif not invalid and ch == "UNCHANGED":
            tn += 1
            tag = "TN"
        elif invalid and ch == "UNCHANGED":
            fn += 1
            tag = "FN"
        elif not invalid and ch == "reject":
            fp += 1
            tag = "FP"
        else:
            tag = "?"  # e.g. Y + rewrite
        rows.append((name, gt, ch, tag))
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "counts": counts,
        "rows": rows,
        "n": len(audits),
    }


def score_1515(compare_csv: Path, cwe: str) -> dict:
    audits: list[dict] = []
    with compare_csv.open(newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row["cwe"] != cwe:
                continue
            rejected = row["rejected"].strip().lower() == "true"
            rewrite = row.get("needs_rewrite", "").strip().lower() == "true"
            if rejected:
                ch = "reject"
            elif rewrite:
                ch = "rewrite"
            else:
                ch = "UNCHANGED"
            audits.append(
                {
                    "row_key": f"x|{cwe}|0|{row['function_name']}",
                    "change": ch,
                }
            )
    resolve = {r["function_name"]: r["Resolve"] for r in csv.DictReader(compare_csv.open(encoding="utf-8-sig")) if r["cwe"] == cwe}
    tmp = Path("/tmp") / f"1515_{cwe}.jsonl"
    tmp.write_text("\n".join(json.dumps(a) for a in audits) + "\n")
    return score_audit(tmp, resolve)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--compare-csv",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "data_annotation_gpt54mini_20260603_1515_rewrites_compare.csv",
    )
    parser.add_argument("--audit", type=Path, action="append", default=[], help="audit.jsonl paths")
    parser.add_argument("--label", action="append", default=[], help="labels parallel to --audit")
    parser.add_argument("--cwe", help="CWE-### if all audits are for one CWE")
    args = parser.parse_args()

    if not args.audit:
        raise SystemExit("provide --audit paths")

    labels = args.label or [p.stem for p in args.audit]
    if len(labels) != len(args.audit):
        raise SystemExit("--label count must match --audit")

    for audit_path, label in zip(args.audit, labels):
        cwe = args.cwe
        if not cwe:
            for part in audit_path.stem.split("_"):
                if part.upper().startswith("CWE"):
                    cwe = part.upper() if part.startswith("CWE") else f"CWE-{part[3:]}"
                    break
            if not cwe:
                raise SystemExit(f"cannot infer CWE from {audit_path}")
        if not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        resolve = load_resolve(args.compare_csv, cwe)
        s = score_audit(audit_path, resolve)
        c = s["counts"]
        print(
            f"{label:40} {cwe}  "
            f"rej={c.get('reject',0)} rw={c.get('rewrite',0)} unch={c.get('UNCHANGED',0)}  "
            f"TP={s['tp']} TN={s['tn']} FP={s['fp']} FN={s['fn']}"
        )


if __name__ == "__main__":
    main()
