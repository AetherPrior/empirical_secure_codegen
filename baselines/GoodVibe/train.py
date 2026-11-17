"""Single-GPU adaptation of the archived GoodVibe gradient/cluster procedure."""
import argparse
import json
import os
from pathlib import Path

# Set before importing torch, including in subprocesses.
gpu = os.environ.get('GOODVIBE_GPU', '3')
if gpu not in ('2', '3'):
    raise ValueError('GoodVibe is restricted to GPUs 2 and 3')
os.environ['CUDA_VISIBLE_DEVICES'] = gpu
os.environ['CUDA_DEVICE_ORDER'] = 'PCI_BUS_ID'
os.environ.setdefault('HF_HOME', '/workspace/hf_home')
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
os.environ.setdefault('OMP_NUM_THREADS', '4')

import sys
import numpy as np
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, set_seed

# This host's cuDNN SDPA planner rejects some Qwen3 sequence shapes. PyTorch's
# flash/memory-efficient SDPA backends support them without changing attention.
torch.backends.cuda.enable_cudnn_sdp(False)

HERE = Path(__file__).resolve().parent
from layout import STATE, artifact_language, checkpoint_path
sys.path.insert(0, str(HERE / 'upstream'))
import util
import fine_tune_clustering as upstream


def write_json(path, value):
    path = Path(path)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)


def load_model(config):
    model = AutoModelForCausalLM.from_pretrained(
        config['model'], revision=config['model_revision'], torch_dtype=torch.bfloat16,
        device_map={'': 0}, attn_implementation='sdpa')
    tokenizer = AutoTokenizer.from_pretrained(config['model'], revision=config['model_revision'])
    tokenizer.padding_side = 'right'
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer


def identify(config, output):
    """Same mean absolute activation-gradient score, with bounded host storage."""
    dest = output / 'safety_neuron_identifiers' / f"Qwen3-8B_{artifact_language(config)}_sn_gradient"
    dest.mkdir(parents=True, exist_ok=True)
    if (dest / 'complete.json').exists():
        return
    codes, labels, _ = util.load_code_datasets(config['language'])
    if config.get('identify_limit'):
        # Smoke tests include both safe and unsafe labels.
        n = config['identify_limit'] // 2
        half = len(codes) // 2
        codes, labels = codes[:n] + codes[half:half+n], labels[:n] + labels[half:half+n]
    model, tokenizer = load_model(config)
    set_seed(config['seed'])
    # Frozen weights still propagate activation gradients; avoid allocating 16GB
    # of unused parameter gradients. Qwen3 has no attention dropout by default.
    model.requires_grad_(False)
    model.enable_input_require_grads()
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={'use_reentrant': False})
    model.config.use_cache = False
    model.train()
    tokens = [tokenizer.encode(s, add_special_tokens=False) for s in ('0', '1')]
    assert all(len(t) == 1 for t in tokens), tokens
    token_ids = [t[0] for t in tokens]
    if config.get('label_token_mode') == 'upstream_ascii':
        token_ids = [ord('0'), ord('1')]
    sums = {}
    def hook(name):
        def accumulate(module, grad_input, grad_output):
            g = grad_output[0].detach().reshape(-1, grad_output[0].shape[-1])
            value = g.abs().mean(0).float().cpu()
            sums[name] = sums.get(name, torch.zeros_like(value)) + value
        return accumulate
    handles = [m.register_full_backward_hook(hook(n)) for n, m in model.named_modules()
               if isinstance(m, torch.nn.Linear)]
    state_path = dest / 'progress.pt'
    start = 0
    if state_path.exists():
        state = torch.load(state_path, weights_only=True)
        sums, start = state['sums'], state['completed']
    for i in range(start, len(codes)):
        prompt = f'''You are an AI that returns only a single number: 1 or 0.
    Return 1 **only** if the given code snippet is unsafe or contains vulnerabilities.
    Return 0 if the code is safe.
    Respond with **only** the number 1 or 0 — no other text, symbols, or explanations.
    {codes[i]}
    '''
        inputs = tokenizer(prompt, return_tensors='pt').to(model.device)
        logits = model(**inputs, logits_to_keep=1).logits[:, -1, token_ids]
        loss = torch.nn.functional.cross_entropy(logits, torch.tensor([labels[i]], device=model.device))
        if not torch.isfinite(loss):
            raise RuntimeError(f'Nonfinite selection loss at sample {i}')
        loss.backward()
        if (i + 1) % 25 == 0 or i + 1 == len(codes):
            tmp = state_path.with_suffix('.tmp')
            torch.save(dict(sums=sums, completed=i+1), tmp)
            tmp.replace(state_path)
            print(f'Identification {i+1}/{len(codes)} loss={loss.item():.4f}', flush=True)
        del inputs, logits, loss
    importance = {k: (v / len(codes)).numpy() for k, v in sums.items()}
    if not importance or not any(np.any(v > 0) for v in importance.values()):
        raise RuntimeError('No nonzero activation gradients')
    neurons = {k: np.argsort(v)[-min(config['top_k'], len(v)):].tolist() for k, v in importance.items()}
    util.save_dict(importance, str(dest / 'gradient_importance_Qwen3-8B.p'))
    util.save_dict(neurons, str(dest / 'safety_neurons_Qwen3-8B.p'))
    util.save_dict(dict(top_k=config['top_k']), str(dest / 'run_metadata_Qwen3-8B.p'))
    write_json(dest / 'complete.json', dict(samples=len(codes), label_token_ids=token_ids,
                                          scored_modules=len(importance)))
    for h in handles:
        h.remove()


def tune(config, output):
    from trl import SFTConfig, SFTTrainer
    from transformers.trainer_utils import get_last_checkpoint
    final = checkpoint_path(config)
    if (output / 'training_complete.json').exists():
        return
    # Reuse authors' clustering, row parametrization, prompts, split and training
    # code verbatim. Redirect artifacts and adapt their TrainingArguments to TRL.
    upstream.__file__ = str(output / 'fine_tune_clustering.py')
    upstream.util_model.load_model = lambda *_args, **_kwargs: load_model(config)
    def training_args(**kwargs):
        kwargs.update(per_device_eval_batch_size=1, seed=config['seed'],
                      max_length=config['max_length'], packing=False,
                      completion_only_loss=False, assistant_only_loss=False,
                      gradient_checkpointing_kwargs={'use_reentrant': False})
        if config.get('max_steps'):
            kwargs.update(max_steps=config['max_steps'], eval_strategy='steps', eval_steps=1,
                          save_strategy='steps', save_steps=1, logging_steps=1)
        return SFTConfig(**kwargs)
    upstream.TrainingArguments = training_args
    class ResumableSFTTrainer(SFTTrainer):
        def train(self, *args, **kwargs):
            last = get_last_checkpoint(self.args.output_dir)
            if last:
                kwargs['resume_from_checkpoint'] = last
            return super().train(*args, **kwargs)
    upstream.SFTTrainer = ResumableSFTTrainer
    os.chdir(output)
    upstream.main(model_id=2, language=config['language'], use_gradient_importance=True,
                  min_silhouette=config['min_silhouette'], num_epochs=config['epochs'])
    if not (final / 'config.json').exists():
        raise RuntimeError(f'Exported checkpoint missing: {final}')
    write_json(output / 'training_complete.json', dict(checkpoint=str(final)))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--stage', choices=['identify', 'tune'], required=True)
    args = p.parse_args()
    config = json.loads(args.config.read_text())
    output = (STATE / config['output']).resolve()
    output.mkdir(parents=True, exist_ok=True)
    frozen = output / 'config.json'
    if frozen.exists() and json.loads(frozen.read_text()) != config:
        raise ValueError('Output belongs to another configuration')
    write_json(frozen, config)
    # Pin dataset revision while retaining the authors' language filtering and
    # comment preprocessing, including its known regex limitations.
    from datasets import load_dataset
    util.load_dataset = lambda name: load_dataset(config['dataset'], revision=config['dataset_revision'])
    if config.get('train_limit') and args.stage == 'tune':
        original = util.load_code_datasets
        def limited(*args, **kwargs):
            result = original(*args, **kwargs)
            return tuple(x[:config['train_limit']] for x in result)
        util.load_code_datasets = limited
    assert torch.cuda.device_count() == 1, f'Expected only physical GPU {gpu}'
    set_seed(config['seed'])
    (identify if args.stage == 'identify' else tune)(config, output)


if __name__ == '__main__':
    main()
