#!/usr/bin/env python3
"""Validate and aggregate the six canonical PurpCode plain-vLLM runs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from pathlib import Path


BENCHMARKS = ("seccodeplt", "cweval", "baxbench")
VARIANTS = ("original", "repaired")
SEEDS = (42, 43, 44)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path):
    return json.loads(path.read_text())


def repository_commit(repo: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        return (repo / "baselines/purpcode/source_commit.txt").read_text().strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    repo = Path(__file__).resolve().parents[2]
    config = read_json(run_dir / "baseline_config.json")
    rows = []
    trace_paths = {}
    score_paths = {}

    for benchmark in BENCHMARKS:
        for variant in VARIANTS:
            label = f"{benchmark}_{variant}"
            arm = run_dir / label
            trace = arm / "generations.jsonl"
            scores = arm / "evaluation/scores.json"
            summary_path = arm / "summary.json"
            for path in (trace, scores, summary_path):
                if not path.is_file():
                    raise FileNotFoundError(path)

            summary = read_json(summary_path)
            if set(map(int, summary["seeds"])) != set(SEEDS):
                raise ValueError(f"{label}: unexpected seeds in summary")

            trace_rows = [json.loads(line) for line in trace.read_text().splitlines() if line.strip()]
            expected = sum(seed_data["n"] for seed_data in summary["seeds"].values())
            if len(trace_rows) != expected:
                raise ValueError(f"{label}: {len(trace_rows)} traces, expected {expected}")
            keys = [(row["case_id"], int(row["seed"])) for row in trace_rows]
            if len(keys) != len(set(keys)):
                raise ValueError(f"{label}: duplicate case/seed traces")
            if any(row.get("status") != "completed" for row in trace_rows):
                raise ValueError(f"{label}: incomplete generation status")

            for seed, seed_data in sorted(summary["seeds"].items(), key=lambda item: int(item[0])):
                rows.append({
                    "benchmark": benchmark,
                    "variant": variant,
                    "seed": int(seed),
                    "n": seed_data["n"],
                    "functionality": seed_data["functionality@1"],
                    "security": seed_data["security@1"],
                    "joint": seed_data["joint@1"],
                    "evaluator_failures": seed_data["evaluator_failures"],
                })
            trace_paths[label] = str(trace)
            score_paths[label] = str(scores)

    analysis = run_dir / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    with (analysis / "summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (analysis / "summary.json").write_text(json.dumps({"rows": rows}, indent=2) + "\n")

    manifest = {
        "repository_commit": repository_commit(repo),
        "baseline_config": config,
        "trace_paths": trace_paths,
        "score_paths": score_paths,
        "trace_sha256": {name: sha256(Path(path)) for name, path in trace_paths.items()},
        "score_sha256": {name: sha256(Path(path)) for name, path in score_paths.items()},
    }
    (analysis / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    for row in rows:
        print(
            f"{row['benchmark']}/{row['variant']} seed={row['seed']} n={row['n']} "
            f"cap={row['functionality']:.2%} sec={row['security']:.2%} "
            f"C&S={row['joint']:.2%} failures={row['evaluator_failures']}"
        )
    print(f"Summary: {analysis / 'summary.csv'}")
    print(f"Manifest: {analysis / 'manifest.json'}")


if __name__ == "__main__":
    main()
