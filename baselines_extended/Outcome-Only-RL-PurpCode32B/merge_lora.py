"""Merge the step-600 LoRA adapter into purpcode-32b-rule-sft without peft.

W' = W + (alpha / r) * B @ A, computed in fp32 and stored back as bf16.
Writes safetensors shards with the base model's file names and index, plus the
base config and tokenizer files, so the output loads as a plain HF model.
"""
import json
import shutil
import sys
from pathlib import Path

import torch
from safetensors import safe_open
from safetensors.torch import save_file

HERE = Path(__file__).resolve().parent
BASE = Path('/workspace/verisec/dataset_curation/verl/models/purpcode-32b-rule-sft')
ADAPTER = HERE / 'checkpoints/global_step_600_lora'
OUT = HERE / 'checkpoints/global_step_600_merged'

cfg = json.loads((ADAPTER / 'adapter_config.json').read_text())
scale = cfg['lora_alpha'] / cfg['r']
OUT.mkdir(parents=True, exist_ok=True)

lora = {}
with safe_open(ADAPTER / 'adapter_model.safetensors', 'pt') as f:
    for k in f.keys():
        lora[k] = f.get_tensor(k).float()
# base_model.model.<module path>.lora_{A,B}.weight -> <module path>.weight
pairs = {}
for k in lora:
    if '.lora_A.weight' in k:
        name = k.replace('base_model.model.', '', 1).replace('.lora_A.weight', '.weight')
        pairs[name] = (k, k.replace('.lora_A.', '.lora_B.'))
print(f'{len(pairs)} LoRA-adapted weights, scale={scale}', flush=True)

index = json.loads((BASE / 'model.safetensors.index.json').read_text())
used = set()
for shard in sorted(set(index['weight_map'].values())):
    tensors = {}
    with safe_open(BASE / shard, 'pt') as f:
        for k in f.keys():
            w = f.get_tensor(k)
            if k in pairs:
                a, b = pairs[k]
                w = (w.float() + scale * (lora[b] @ lora[a])).to(torch.bfloat16)
                used.add(k)
            tensors[k] = w.contiguous()
    save_file(tensors, OUT / shard, metadata={'format': 'pt'})
    print('wrote', shard, flush=True)

missing = set(pairs) - used
assert not missing, f'adapter weights not found in base: {sorted(missing)[:5]}'
shutil.copy2(BASE / 'model.safetensors.index.json', OUT / 'model.safetensors.index.json')
for name in BASE.iterdir():
    if name.suffix in ('.json', '.txt', '.jinja') and not (OUT / name.name).exists():
        shutil.copy2(name, OUT / name.name)
(OUT / 'merge_provenance.json').write_text(json.dumps(dict(
    base=str(BASE), adapter=str(ADAPTER), lora_rank=cfg['r'], lora_alpha=cfg['lora_alpha'],
    merged_weights=len(used),
    source_run='purpcode_32b_rulesft_lora_outcome_rl700_20261106T210907Z', source_step=600), indent=2) + '\n')
print('done', len(used), 'weights merged', flush=True)
