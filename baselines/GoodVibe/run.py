"""One sequential campaign worker on GPU 2 or 3, with per-stage logs."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
from layout import BENCHMARKS as ROOT, STATE, checkpoint_path
TRAIN_PY = STATE / '.venv/bin/python'
EVAL_PY = Path('/opt/conda/envs/vllm/bin/python')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--evaluation-only', action='store_true')
    parser.add_argument('--eval-config', type=Path, default=STATE / 'configs/evaluation.json')
    parser.add_argument('--output-dir', type=Path, default=STATE / 'outputs')
    parser.add_argument('--gpu', choices=['2', '3'], default='3')
    parser.add_argument('--languages', nargs='+', choices=['cpp', 'py', 'js'], default=['cpp', 'py', 'js'])
    parser.add_argument('--wait-pid', type=int, help='Wait for an adopted training process before resuming')
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if not output.is_relative_to(STATE):
        parser.error('Outputs must stay within baselines/GoodVibe')
    cfg = json.loads(args.eval_config.read_text())
    selected_jobs = [j for j in cfg['jobs'] if j['checkpoint'] in args.languages
                     and str(j.get('gpu', args.gpu)) == args.gpu]
    if not args.evaluation_only and output != STATE / 'outputs':
        parser.error('Custom output directories require --evaluation-only')
    logs = output / 'logs'
    logs.mkdir(parents=True, exist_ok=True)
    lock = (output / f'campaign_gpu{args.gpu}.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    language_locks = []
    lock_names = ([f"job_{j['checkpoint']}_{j['benchmark']}_{'_'.join(j['languages'])}"
                   for j in selected_jobs] if args.evaluation_only else args.languages)
    for slug in sorted(set(lock_names)):
        handle = (output / f'campaign_{slug}.lock').open('w')
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        language_locks.append(handle)
    status_path = output / f'status_gpu{args.gpu}.json'
    if args.wait_pid and not args.dry_run:
        status_path.write_text(json.dumps(dict(status='waiting_for_existing_training',
            pid=args.wait_pid, gpu=args.gpu, languages=args.languages), indent=2))
        while True:
            try:
                state = Path(f'/proc/{args.wait_pid}/stat').read_text().split(') ', 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state == 'Z':
                break
            time.sleep(5)
    env = dict(os.environ, CUDA_VISIBLE_DEVICES=args.gpu, GOODVIBE_GPU=args.gpu, CUDA_DEVICE_ORDER='PCI_BUS_ID',
               PYTHONDONTWRITEBYTECODE='1',
               VLLM_CACHE_ROOT=str(output / 'cache/vllm'),
               TORCHINDUCTOR_CACHE_DIR=str(output / 'cache/torchinductor'),
               TRITON_CACHE_DIR=str(output / 'cache/triton'),
               HF_HOME='/workspace/hf_home', PYTHONUNBUFFERED='1', OMP_NUM_THREADS='4',
               VLLM_USE_FLASHINFER_SAMPLER='0', VLLM_USE_DEEP_GEMM='0')
    jobs = []
    if not args.evaluation_only:
        for slug in args.languages:
            for stage in ['identify', 'tune']:
                jobs.append((slug + '_' + stage, [str(TRAIN_PY), str(HERE / 'train.py'),
                            '--config', str(STATE / f'configs/{slug}.json'), '--stage', stage]))
    for job in selected_jobs:
        slug, bench = job['checkpoint'], job['benchmark']
        job_name = f"{slug}_{bench}_{'_'.join(job['languages'])}"
        checkpoint = checkpoint_path(json.loads((STATE / f'configs/{slug}.json').read_text()))
        command = [str(EVAL_PY), str(HERE / 'evaluation/run_plain_vllm.py'), '--model', str(checkpoint),
                   '--benchmarks-root', str(ROOT),
                   '--model-label', f'goodvibe_qwen3_8b_{slug}', '--benchmark', bench,
                   '--variant', cfg['variant'], '--out', str(output / 'evaluation' / job_name),
                   '--languages', *job['languages'], '--seeds', *map(str, cfg['seeds']), '--tp', '1',
                   '--baxbench-port-base', str(cfg.get('port_bases', {}).get(args.gpu,
                       36000 if args.gpu == '3' else 37000))]
        for key in ['temperature', 'top_p', 'max_tokens', 'max_model_len', 'concurrency',
                    'eval_workers', 'gpu_memory_utilization']:
            command += ['--' + key.replace('_', '-'), str(cfg[key])]
        command += ['--enable-thinking' if cfg['enable_thinking'] else '--no-enable-thinking']
        jobs.append((job_name, command))
    for name, command in jobs:
        print(name, command, flush=True)
        if args.dry_run:
            continue
        status = dict(stage=name, status='running', started=time.time(), command=command,
                      gpu=args.gpu, languages=args.languages)
        status_path.write_text(json.dumps(status, indent=2))
        with (logs / (name + '.log')).open('a') as log:
            result = subprocess.run(command, cwd=ROOT.parent, env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            status.update(status='failed', returncode=result.returncode)
            status_path.write_text(json.dumps(status, indent=2))
            sys.exit(result.returncode)
        if '--benchmark' in command:
            subprocess.run([sys.executable, str(HERE / 'aggregate.py'),
                            '--eval-config', str(args.eval_config.resolve()),
                            '--output-dir', str(output)], check=True)
    if not args.dry_run:
        status_path.write_text(json.dumps(dict(status='complete', finished=time.time(), gpu=args.gpu)))


if __name__ == '__main__':
    main()
