"""Run a pinned ProSec DPO adaptation on four GPUs."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent
PY = HERE / '.venv/bin/python'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=HERE / 'configs/qwen3_8b_prosec_all_400step.json')
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text())
    OUT = HERE / 'outputs' / cfg.get('run_name', args.config.stem)
    if not OUT.resolve().is_relative_to(HERE):
        raise ValueError('Outputs must remain in this baseline')
    OUT.mkdir(parents=True, exist_ok=True)
    lock = (OUT / 'campaign.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    data = HERE / cfg.get('train_jsonl', 'data/prosec_python.jsonl')
    if hashlib.sha256(data.read_bytes()).hexdigest() != cfg['data_sha256']:
        raise ValueError('Training data changed')
    cmd = [str(PY), '-m', 'torch.distributed.run', '--standalone', '--nnodes=1',
           '--nproc-per-node=4', str(HERE / 'simple_gen/py/7_train_dpo.py'),
           '--model', cfg['model'], '--revision', cfg['model_revision'],
           '--train-jsonl', str(data), '--output-dir', str(OUT / 'adapter'),
           '--loss-type', 'sigmoid', '--no-enable-thinking', '--bf16',
           '--gradient-checkpointing', '--logging-steps', '1', '--save-steps', '50',
           '--save-total-limit', '2', '--eval-steps', '100']
    for key in ['max_steps', 'seed', 'per_device_train_batch_size',
                'gradient_accumulation_steps', 'learning_rate', 'beta',
                'max_length', 'max_prompt_length', 'lora_r', 'lora_alpha',
                'lora_dropout', 'eval_ratio']:
        cmd += ['--' + key.replace('_', '-'), str(cfg[key])]
    checkpoints = sorted((OUT / 'adapter').glob('checkpoint-*'),
                         key=lambda p: int(p.name.split('-')[-1]))
    if checkpoints:
        cmd += ['--resume-from-checkpoint', str(checkpoints[-1])]
    cache = HERE / 'outputs/cache'
    env = dict(os.environ, CUDA_VISIBLE_DEVICES='0,1,2,3', CUDA_DEVICE_ORDER='PCI_BUS_ID',
               HF_HOME='/workspace/hf_home', HF_DATASETS_CACHE=str(cache / 'datasets'),
               TORCHINDUCTOR_CACHE_DIR=str(cache / 'inductor'), TRITON_CACHE_DIR=str(cache / 'triton'),
               PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1', TOKENIZERS_PARALLELISM='false',
               OMP_NUM_THREADS='4', WANDB_DISABLED='true')
    manifest = dict(config=cfg, command=cmd, started=time.time(),
                    trainer_sha256=hashlib.sha256((HERE / 'simple_gen/py/7_train_dpo.py').read_bytes()).hexdigest())
    (OUT / 'run.json').write_text(json.dumps(manifest, indent=2) + '\n')
    status = OUT / 'status.json'
    status.write_text(json.dumps(dict(status='training', started=time.time(), gpus=cfg['gpus'])))
    with (OUT / 'training.log').open('a') as log:
        result = subprocess.run(cmd, cwd=HERE, env=env, stdout=log, stderr=subprocess.STDOUT)
    status.write_text(json.dumps(dict(status='complete' if result.returncode == 0 else 'failed',
                                      returncode=result.returncode, finished=time.time()), indent=2))
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
