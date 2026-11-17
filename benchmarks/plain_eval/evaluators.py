"""Evaluate final answers using frozen benchmark sources in containers."""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .common import read_json, write_json
from .common import configure_paths


def cweval(out, model, condition, rows, destination):
    import shutil
    # CWEval completes Go files with `goimports -w` and ignores a failure, so a broken or missing goimports silently leaves the imports of the
    # appended main() unresolved and every Go task fails to compile. goimports needs the go toolchain too. Put both on PATH and check that
    # it really adds a missing import before scoring anything.
    import subprocess, tempfile
    os.environ['PATH'] = f"{Path.home()}/go/bin:/opt/conda/envs/cweval/go/bin:" + os.environ['PATH']
    if shutil.which('goimports') is None or shutil.which('go') is None:
        raise RuntimeError('goimports/go not found: CWEval Go scoring needs both')
    with tempfile.TemporaryDirectory() as t:
        probe = Path(t) / 'p.go'
        probe.write_text('package main\nfunc main() { fmt.Println(os.Args) }\n')
        subprocess.run(['goimports', '-w', str(probe)], capture_output=True, timeout=120)
        if '"fmt"' not in probe.read_text() or '"os"' not in probe.read_text():
            raise RuntimeError('goimports did not add the missing imports: CWEval Go scoring would be wrong')
    frozen = out / 'frozen/cweval'
    sys.path.insert(0, str(frozen))
    os.chdir(frozen)
    from cweval import evaluate as ev
    original = ev.Container
    image = read_json(out / 'preflight.json')['cweval_image']

    class FrozenContainer(original):
        def __init__(self, **kwargs):
            kwargs['image'] = image
            super().__init__(**kwargs)
            # Replace evaluator code and reference sources in this ephemeral
            # container. The existing image supplies only the pinned toolchain.
            for name in ('cweval', 'benchmark'):
                self.copy_to(str(frozen / name), ev.Evaler.repo_path_in_docker + '/' + name)

    ev.Container = FrozenContainer
    evalpath = destination / 'artifacts'
    for row in rows:
        raw = evalpath / f'generated_{row["seed"] - 42}' / row['case_id'].replace('_task.', '_raw.')
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text(row.get('answer', '') if row['status']=='completed' else '')
    evaluator = ev.Evaler(str(evalpath), num_proc=8)
    evaluator.pipeline(docker=True)
    results = {}
    for p in evalpath.glob('generated_*/res.json'):
        seed = 42 + int(p.parent.name.removeprefix('generated_'))
        for key, value in read_json(p).items():
            # Result paths are absolute paths inside the container.
            relative = key.split(p.parent.name + '/', 1)[-1]
            case_id = relative.removesuffix('_test.py')
            results[(case_id, seed)] = value
    scores = []
    for row in rows:
        stem = str(Path(row['case_id']).with_suffix('')).removesuffix('_task')
        value = results.get((stem,row['seed']))
        valid = value is not None and value.get('functional') is not None and value.get('secure') is not None
        generated = row['status']=='completed'
        functional = bool(valid and generated and value['functional'])
        secure = bool(valid and generated and value['secure'])
        scores.append(dict(case_id=row['case_id'], seed=row['seed'], functionality=functional,
            security=secure, joint=functional and secure, evaluator_failure=not valid,
            generation_failure=not generated, raw_result=value))
    return scores


def baxbench_task_scores(rows, evaluate, workers=16):
    """Advance samples within each task independently, as native TaskHandler does."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    grouped = {}
    for row in rows:
        grouped.setdefault(row['case_id'], []).append(row)

    def task_samples(samples):
        return [evaluate(row) for row in sorted(samples, key=lambda row: row['seed'])]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(task_samples, samples) for samples in grouped.values()]
        for future in as_completed(futures):
            yield from future.result()


def baxbench_port_base(out, model, condition):
    """Reserve a separate 64-port range for every condition in a campaign."""
    config = read_json(out/'config.json')
    base = config.get('baxbench_port_base', 30000)
    campaign = out/'campaign.json'
    if not campaign.exists():
        return config.get('evaluator_port_base', base)
    spec = read_json(campaign)
    labels = [str(b) for b in spec['budgets']]
    ordinal = spec['models'].index(model)*len(labels) + labels.index(str(condition))
    port = base + 64*ordinal
    if port < 1024 or port+31 > 65535:
        raise ValueError('Invalid BaxBench condition port range')
    return port


def baxbench(out, model, condition, rows, destination):
    import multiprocessing
    from dataclasses import replace
    frozen = out / 'frozen/baxbench'
    sys.path.insert(0, str(frozen / 'src'))
    from env import all_envs
    from scenarios import all_scenarios
    from prompts import Parser
    from tasks import Task, SlotManager
    from .baxbench_adapter import ExtraArgs
    # Agent scaffolding in the historical benchmark mounted Docker's host
    # socket. Generated applications need only their two published ports.
    # Keep evaluation isolated from the host Docker daemon.
    import uuid
    import docker
    from env.base import Env
    client = docker.from_env()
    pins = read_json(out/'container_images.json')['baxbench']
    pinned_envs = []
    for env in all_envs:
        dockerfile = env.dockerfile
        if env.language.lower() in ('python','javascript'):
            for tag, pin in pins.items():
                dockerfile = dockerfile.replace('FROM '+tag, 'FROM '+pin['digest'])
        # Environments outside Python/JavaScript install unpinned dependencies that have drifted since BaxBench was released; restore
        # builds that work with the pinned base images. (Python/JavaScript are pinned above and are not touched.)
        if env.language.lower() == 'go':
            dockerfile = dockerfile.replace('goimports@latest', 'goimports@v0.38.0')   # @latest now needs Go >= 1.26
        elif env.language.lower() == 'rust':
            dockerfile = dockerfile.replace('FROM rust:1.83.0-alpine3.20', 'FROM rust:1.90.0-alpine3.22')   # current crates (actix-web, uuid) need rustc >= 1.89
        elif env.language.lower() == 'ruby':
            dockerfile = dockerfile.replace('RUN bundler install', 'RUN echo \'gem "json", "< 2.10"\' >> Gemfile\nRUN bundler install')   # Rails 8.0 passes quirks_mode, removed in json 2.10
        # Benchmark environments are frozen dataclasses. Construct evaluation
        # copies so the original prompt environments remain unchanged.
        pinned_envs.append(replace(env,dockerfile=dockerfile))
    def isolated_container(self, image_id, use_port, agent):
        return client.containers.run(image_id, name=f'injection_bax_{uuid.uuid4().hex}',
            detach=True, ports={f'{self.port}/tcp':use_port,f'{self.agent_port}/tcp':agent},
            auto_remove=False, mem_limit=2**30)
    Env.run_docker_container = isolated_container
    original_build = Env.build_docker_image
    def recorded_build(self, files, additional_docker_commands, logger, no_cache):
        image_id = original_build(self,files,additional_docker_commands,logger,no_cache)
        metadata = destination/'images'/image_id.replace(':','_')
        metadata.mkdir(parents=True,exist_ok=True)
        write_json(metadata/'image.json',dict(image_id=image_id,framework=self.id,
            dockerfile=self._format_dockerfile(self.entrypoint_cmd,additional_docker_commands)))
        dependencies = client.containers.run(image_id,entrypoint=['sh','-c'],
            command=['python3 -m pip freeze 2>/dev/null || npm ls --json --all 2>/dev/null; true'],
            remove=True,network_disabled=True)
        (metadata/'dependencies.txt').write_bytes(dependencies)
        container = client.containers.create(image_id,entrypoint='sh')
        try:
            for source in ('/app/package-lock.json',):
                try:
                    archive, _ = container.get_archive(source)
                    with (metadata/'package-lock.tar').open('wb') as f:
                        for block in archive:
                            f.write(block)
                except docker.errors.NotFound:
                    pass
        finally:
            container.remove()
        return image_id
    Env.build_docker_image = recorded_build
    extra = ExtraArgs(llm_model=model, sample_seeds=[42,43,44])
    envs, scenarios = {e.id:e for e in pinned_envs}, {s.id:s for s in all_scenarios}
    artifacts = destination / 'artifacts'
    logger = logging.getLogger('injection.baxbench')
    checkpoint=destination/'scores_checkpoint.json'
    cached=read_json(checkpoint) if checkpoint.exists() else []
    bykey={(r['case_id'],r['seed']):r for r in cached}
    def one(row, manager):
        scenario, framework = row['case_id'].split('/', 1)  # a framework id may contain '/', e.g. Go-net/http
        task = Task(envs[framework], scenarios[scenario], model, 0.6, 'openapi', 'none', False, extra)
        sample = row['seed'] - 42
        score = dict(case_id=row['case_id'],seed=row['seed'],functionality=False,security=False,joint=False,
                     evaluator_failure=False,generation_failure=row['status']!='completed')
        if row['status'] != 'completed':
            return score
        try:
            files = Parser(task.env, logger).parse_response(row['answer'])
            # Never allow model file names to escape the generated app directory.
            for path in files:
                if Path(path).is_absolute() or '..' in Path(path).parts:
                    raise ValueError('Unsafe generated file path')
            task.save_code(files, artifacts, sample)
            task.test_code(artifacts, [sample], manager, 120, False)
            result = read_json(task.get_test_results_json_path(artifacts,sample))
            log_path = task.get_test_results_json_path(artifacts,sample).parent / 'test.log'
            log_text = log_path.read_text(errors='replace') if log_path.exists() else ''
            if any(m in log_text for m in ('failed to bind host port', 'port is already allocated',
                                           'failed to set up container networking', 'driver failed programming external connectivity')):
                raise RuntimeError('BaxBench infrastructure failure: Docker could not start or network the app container')
            score['raw_result'] = result
            functional = result['num_total_ft'] > 0 and result['num_passed_ft']==result['num_total_ft'] and result['num_ft_exceptions']==0
            secure = result['num_total_st'] > 0 and not result['cwes'] and result['num_st_exceptions']==0
            score.update(functionality=functional, security=secure, joint=functional and secure,
                         evaluator_failure=False,
                         test_exceptions=bool(result['num_ft_exceptions']+result['num_st_exceptions']))
        except Exception as exc:
            score.update(evaluator_failure=True,error=f'{type(exc).__name__}: {exc}')
        return score
    with multiprocessing.Manager() as manager:
        ports = SlotManager(manager, 32, baxbench_port_base(out, model, condition))
        # Each task advances through its own samples without a global seed barrier.
        pending = [r for r in rows if (r['case_id'], r['seed']) not in bykey]
        for score in baxbench_task_scores(pending, lambda row: one(row, ports)):
            bykey[(score['case_id'],score['seed'])] = score
            write_json(checkpoint,list(bykey.values()))
            print(f'Baxbench scored {len(bykey)} available requests',flush=True)
    return [bykey[(r['case_id'],r['seed'])] for r in rows]


