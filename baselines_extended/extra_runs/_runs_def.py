"""Score every finished extra-language generation (CWEval Go, BaxBench Go/PHP/Ruby/Rust) with benchmarks/run_plain_vllm.py --extra --operation evaluate.
Rescans every few minutes, so it picks up runs as the generation queues finish them. A run is scored once all its tasks x seeds are present."""
import json, subprocess, sys, time
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
PY = '/opt/conda/envs/vllm/bin/python'
N = dict(cweval=19, baxbench=168)
# (label, benchmark, directory) -- every place an extras run can land
def runs():
    out = []
    q = REPO / 'baselines_extended/extra_runs'
    for d in sorted(q.glob('*/extra_*')):
        if d.is_dir(): out.append((d.parent.name, d.name.removeprefix('extra_'), d))
    for m in ('gpt-4o', 'gpt-6.1-sol'):
        for b in ('cweval', 'baxbench'): out.append((m, b, REPO / f'baselines/OpenAI-Frontier/outputs/{m}/repaired/extra_{b}'))
    for b in ('cweval', 'baxbench'): out.append(('cosec', b, REPO / f'baselines/cosec-vllm/outputs_extra/{b}_repaired_extra'))
    for r in ('safecoder_data_think', 'safecoder_ours_think'):
        for b in ('cweval', 'baxbench'): out.append((r.replace('_think', ''), b, REPO / f'baselines_extended/dpo/outputs/prosec_merged_eval/{r}/extra_{b}'))
    for r in ('prosec_data_nothink', 'prosec_ours_nothink', 'safecoder_data_nothink', 'safecoder_ours_nothink'):
        for b in ('cweval', 'baxbench'): out.append((r, b, REPO / f'baselines_extended/dpo/outputs/prosec_merged_eval/{r}/extra_{b}'))
    for m in ('orig', 'ours'):
        for b in ('cweval', 'baxbench'): out.append((f'sven-{m}', b, REPO / f'baselines/SafeCoder/sven_eval/{m}/extra_{b}'))
    for b in ('cweval', 'baxbench'): out.append(('rescue', b, REPO / f'baselines/RESCUE/outputs/run/extra_{b}'))
    return out

