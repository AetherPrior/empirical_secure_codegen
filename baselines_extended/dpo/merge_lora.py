"""Merge a PEFT LoRA adapter into its base model without peft: W += (alpha/r) * B @ A (bf16 weights, fp32 math)."""
import json, shutil, sys
from pathlib import Path
import torch
from safetensors import safe_open
from safetensors.torch import load_file, save_file
base, adapter, out = map(Path, sys.argv[1:4])
cfg = json.load(open(adapter / 'adapter_config.json')); scale = cfg['lora_alpha'] / cfg['r']
ad = load_file(str(adapter / 'adapter_model.safetensors'))
out.mkdir(parents=True, exist_ok=True)
for f in base.glob('*'):
    if f.suffix != '.safetensors' and f.is_file(): shutil.copy2(f.resolve(), out / f.name)
used = 0
for shard in sorted(base.glob('*.safetensors')):
    w = load_file(str(shard.resolve()))
    for k in list(w):
        if not k.endswith('.weight') or not ('layers.' in k or k == 'lm_head.weight'): continue
        stem = k[:-len('.weight')]
        a = ad.get(f'base_model.model.{stem}.lora_A.weight'); b = ad.get(f'base_model.model.{stem}.lora_B.weight')
        if a is None: continue
        delta = scale * (b.float() @ a.float())
        if k == 'lm_head.weight':  # SafeCoder resizes the vocabulary to the tokenizer; rows beyond it are padding and stay unchanged
            n = delta.shape[0]; w[k][:n] = (w[k][:n].float() + delta).to(w[k].dtype)
        else:
            w[k] = (w[k].float() + delta).to(w[k].dtype)
        used += 1
    save_file(w, str(out / shard.name), metadata={'format': 'pt'})
print('merged modules', used, 'of adapter tensors', len(ad) // 2)
assert used == len(ad) // 2
