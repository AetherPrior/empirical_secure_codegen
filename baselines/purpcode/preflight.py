#!/usr/bin/env python3
"""Read-only server checks for the canonical plain-vLLM baseline."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PINS_DIR = REPO_ROOT / "benchmarks" / "plain_eval"


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, text=True, capture_output=True, check=False)
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def main() -> None:
    errors: list[str] = []

    if os.environ.get("CUDA_VISIBLE_DEVICES") != "0":
        errors.append("Set CUDA_VISIBLE_DEVICES=0 before launching this baseline.")

    for module in ("vllm", "transformers", "docker"):
        try:
            imported = importlib.import_module(module)
            version = getattr(imported, "__version__", "installed")
            print(f"Python dependency: {module} {version}")
        except Exception as exc:
            errors.append(f"Python cannot import {module}: {type(exc).__name__}: {exc}")

    gpu = run([
        "nvidia-smi",
        "-i",
        "0",
        "--query-compute-apps=pid,process_name,used_memory",
        "--format=csv,noheader,nounits",
    ])
    if gpu.returncode != 0:
        errors.append(f"Cannot inspect GPU 0 with nvidia-smi: {gpu.stderr.strip()}")
    elif gpu.stdout.strip():
        errors.append("GPU 0 has active compute processes:\n" + gpu.stdout.strip())
    else:
        print("GPU 0: no active compute process")

    docker_info = run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if docker_info.returncode != 0:
        errors.append(
            "Docker daemon is unavailable to this user: "
            + (docker_info.stderr.strip() or docker_info.stdout.strip())
        )
    else:
        print(f"Docker server: {docker_info.stdout.strip()}")

        container_images = json.loads((PINS_DIR / "container_images.json").read_text())
        cweval = json.loads((PINS_DIR / "preflight.json").read_text())["cweval_image"]
        expected = [
            ("SecCodePLT/Python", container_images["baxbench"]["python:3.12-alpine"]),
            ("BaxBench/Node", container_images["baxbench"]["node:22.12-alpine3.20"]),
            ("CWEval", {"image_id": cweval, "digest": "co1lin/cweval:latest"}),
        ]
        missing: list[tuple[str, dict[str, str]]] = []
        for label, pin in expected:
            inspected = run(["docker", "image", "inspect", pin["image_id"], "--format", "{{.Id}}"])
            actual = inspected.stdout.strip()
            if inspected.returncode != 0 or actual != pin["image_id"]:
                missing.append((label, pin))
            else:
                print(f"Pinned image: {label} {actual}")

        if missing:
            lines = ["Required pinned evaluator images are absent:"]
            for label, pin in missing:
                lines.append(f"  {label}: {pin['image_id']}")
            lines.extend([
                "Pull candidates, then rerun preflight:",
                f"  docker pull {container_images['baxbench']['python:3.12-alpine']['digest']}",
                f"  docker pull {container_images['baxbench']['node:22.12-alpine3.20']['digest']}",
                "  docker pull co1lin/cweval:latest",
                "Do not edit the pinned IDs if a pull resolves to a different image; ask the authors for the pinned image.",
            ])
            errors.append("\n".join(lines))

    if errors:
        print("\nPreflight FAILED:", file=sys.stderr)
        for error in errors:
            print(f"\n- {error}", file=sys.stderr)
        raise SystemExit(1)

    print("Preflight passed; no files, images, or processes were changed.")


if __name__ == "__main__":
    main()
