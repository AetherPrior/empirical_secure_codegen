#!/usr/bin/env python3
"""Add a trivial ``candidate_c`` (or another field) to JSONL rows that are missing it.

Use this when an external evaluation script expects a C source column but the harness pipeline
does not generate solutions yet. See ``utils.stub_candidate_c_source`` for the stub shape.

Examples:
  python3 inject_stub_candidate_jsonl.py -i tasks.jsonl -o tasks.with_stub.jsonl
  python3 inject_stub_candidate_jsonl.py -i tasks.jsonl -o out.jsonl --overwrite
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from utils import read_jsonl, stub_candidate_c_source


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-jsonl", type=Path, required=True)
    p.add_argument("--output-jsonl", type=Path, required=True)
    p.add_argument("--field", type=str, default="candidate_c", help="JSONL key to set (default: candidate_c)")
    p.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace the field even when it is already non-empty.",
    )
    args = p.parse_args()

    rows = read_jsonl(args.input_jsonl)
    out: list[dict] = []
    for row in rows:
        r = dict(row)
        fn = r.get("function_name") or "task"
        cur = r.get(args.field, "")
        if args.overwrite or not (isinstance(cur, str) and cur.strip()):
            r[args.field] = stub_candidate_c_source(str(fn))
        out.append(r)

    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.output_jsonl.open("w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {len(out)} rows -> {args.output_jsonl}")


if __name__ == "__main__":
    main()
