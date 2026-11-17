"""
Expected directory structure:

benchmark
├── core
│   ├── c
│   │   ├── cwe_022_0_c_task.c
│   └── py
│   |   ├── cwe_020_0_task.py
└── lang

evals
├── eval_241110_014704
│   ├── generated_0
│   │   ├── core
│   │   │   ├── c
│   │   │   │   ├── cwe_022_0_c_raw.c    <--- to generate
│   │   │   └── py
│   │   │       ├── cwe_020_0_raw.py
│   │   └── lang
│   └── generated_1
└── pytest.ini
"""

import datetime
import json
import os
import shutil
from typing import Any, Dict, List, Optional

import fire
from cweval.ai import AIAPI
from cweval.commons import BENCHMARK_DIR, LANGS
from cweval.ppt import make_prompt
from natsort import natsorted
from p_tqdm import p_map
from tqdm import tqdm


class Gener:

    begin_prompt_anchor = 'BEGIN PROMPT'
    begin_solution_anchor = 'BEGIN SOLUTION'

    def __init__(
        self,
        eval_path: str = '',
        model: str = 'gpt-4o-mini-2024-07-18',
        ppt: str = 'direct',
        num_proc: int = 8,
        langs: List[str] = LANGS,
        exclude_path: List[str] = [],
        include_path: List[str] = [],
        system_prompt: str = '',
        system_prompt_file: str = '',
        no_system_prompt: bool = False,
        backend: str = 'api',
        codex_reasoning_effort: str = 'none',
        claude_effort: str = 'low',
        agent_max_budget_usd: float = None,
        agent_timeout: int = 600,
        # AI parameters
        n: int = 20,
        max_completion_tokens: int = 2048,
        temperature: float = 0.8,
        sample_seeds: Optional[List[int]] = None,
        resume: bool = False,
        **kwargs,
    ):
        self.model = model
        self.ppt = ppt
        self.num_proc = num_proc
        self.langs = langs
        self.exclude_path = exclude_path
        self.include_path = include_path
        if no_system_prompt:
            system_prompt = ''
        elif system_prompt_file:
            with open(system_prompt_file, 'r') as f:
                system_prompt = f.read()
        elif backend in {'codex', 'claude'}:
            # Keep CLI-agent benchmark calls prompt-only by default.  An
            # explicit --system_prompt/--system_prompt_file still opts in.
            system_prompt = ''
        self.system_prompt = system_prompt.strip() if system_prompt else ''
        if sample_seeds is not None and len(sample_seeds) != n:
            raise ValueError(
                f'sample_seeds must contain exactly n={n} values, got '
                f'{len(sample_seeds)}'
            )
        self.sample_seeds = list(sample_seeds) if sample_seeds is not None else None
        print(f'Using langs: {self.langs}')
        self.ai_kwargs = {
            'retry_empty': resume,
            'n': n,
            'max_completion_tokens': max_completion_tokens,
            'temperature': temperature,
            'backend': backend,
            'codex_reasoning_effort': codex_reasoning_effort,
            'claude_effort': claude_effort,
            'agent_max_budget_usd': agent_max_budget_usd,
            'agent_timeout': agent_timeout,
            **kwargs,
        }

        if not eval_path:
            self.eval_path = os.path.join(
                'evals', f'eval_{datetime.datetime.now().strftime("%y%m%d_%H%M%S")}'
            )
        else:
            # check if eval_path exists
            if os.path.exists(eval_path) and not resume:
                flag = (
                    input(f'{eval_path} already exists, overwrite? (y/n): ')
                    .strip()
                    .lower()
                )
                if flag != 'y':
                    print(f'Exiting...')
                    exit(0)

            self.eval_path = eval_path

        self.cases = self._get_cases()

    def _get_cases(self) -> Dict[str, Dict[str, str]]:
        cases: Dict[str, str] = {}
        for root, _, files in os.walk(BENCHMARK_DIR):
            if '__pycache__' in root:
                continue
            for file in natsorted(files):
                file_wo_ext, ext = os.path.splitext(file)
                task_file_path = os.path.join(root, file)
                lang = ext[1:]
                # filtering
                if not (ext and file_wo_ext.endswith('_task')):
                    continue
                if lang not in self.langs:
                    continue
                if any(exclude in task_file_path for exclude in self.exclude_path):
                    continue
                if self.include_path and not any(
                    include in task_file_path for include in self.include_path
                ):
                    continue
                # gather code prompt
                with open(task_file_path, 'r') as f:
                    task_code = f.read()
                begin_solution_line_src = ''
                for line in task_code.splitlines():
                    if self.begin_solution_anchor in line:
                        begin_solution_line_src = line
                        break
                if not begin_solution_line_src:
                    raise ValueError(f'No solution found in {task_file_path}')
                code_prompt = (
                    task_code.split(self.begin_prompt_anchor)[-1]
                    .split(begin_solution_line_src)[0]
                    .strip()
                )

                rel_task_file_path = os.path.relpath(task_file_path, BENCHMARK_DIR)
                gen_file_path_template = os.path.join(
                    self.eval_path,
                    'generated_{index}',
                    rel_task_file_path.replace('_task', '_raw'),
                )

                cases[task_file_path] = {
                    'task_file_path': task_file_path,
                    'code_prompt': code_prompt,
                    'lang': lang,
                    'out_path_template': gen_file_path_template,
                }

        return cases

    @staticmethod
    def _gen_case(
        ai: str,
        ppt: str,
        case: Dict[str, str],
        ai_kwargs: Dict[str, Any],
        system_prompt: str,
        rank: int,
        sample_seeds: Optional[List[int]],
    ) -> None:
        num_samples = ai_kwargs.get('n', 1)
        if sample_seeds is not None:
            # Send one request per sample so samples 0, 1, and 2 are tied to
            # seeds 42, 43, and 44 rather than sharing one opaque batched RNG
            # stream. This also makes interrupted runs resumable by sample.
            for i, seed in enumerate(sample_seeds):
                out_path = case['out_path_template'].format(index=i)
                if os.path.exists(out_path) and (not ai_kwargs.get('retry_empty', False) or os.path.getsize(out_path) > 0):
                    continue
                request_kwargs = ai_kwargs.copy()
                request_kwargs.pop('retry_empty', None)
                request_kwargs['n'] = 1
                request_kwargs['seed'] = seed
                aiapi = AIAPI(ai, **request_kwargs)
                prompt = make_prompt(ppt)
                try:
                    responses = prompt.req_ai(
                        aiapi,
                        case['lang'],
                        case['code_prompt'],
                        system_prompt=system_prompt,
                        metadata={
                            k: v
                            for k, v in case.items()
                            if k not in ['code_prompt', 'lang']
                        },
                    )
                    response = responses[0] if responses else ''
                except Exception as exc:
                    print(
                        f'Generation failed for {case["task_file_path"]} '
                        f'sample {i} seed {seed}: {type(exc).__name__}: {exc}',
                        flush=True,
                    )
                    response = ''
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, 'w') as f:
                    f.write(response)
            return

        for i in range(num_samples):
            out_path = case['out_path_template'].format(index=i)
            # An existing file records an attempted sample, including an
            # empty generation.  Do not silently retry empty outputs.
            if not os.path.exists(out_path):
                break
        else:
            print(
                f'{case["out_path_template"]} already completed, skipping', flush=True
            )
            return

        aiapi = AIAPI(ai, **ai_kwargs)
        prompt = make_prompt(ppt)
        try:
            resps = prompt.req_ai(
                aiapi,
                case['lang'],
                case['code_prompt'],
                system_prompt=system_prompt,
                metadata={
                    k: v for k, v in case.items() if k not in ['code_prompt', 'lang']
                },
            )
        except Exception as exc:
            # Record a failed generation as an empty sample.  This prevents
            # multiprocessing from trying to pickle provider exceptions
            # (notably OpenAI APIStatusError) and makes the failure countable
            # without retrying the task.
            print(
                f'Generation failed for {case["task_file_path"]}: '
                f'{type(exc).__name__}: {exc}',
                flush=True,
            )
            resps = [''] * num_samples
        for i, resp in enumerate(resps):
            out_path = case['out_path_template'].format(index=i)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'w') as f:
                f.write(resp)

    def gen(self) -> None:
        p_map(
            self._gen_case,
            [self.model] * len(self.cases),
            [self.ppt] * len(self.cases),
            self.cases.values(),
            [self.ai_kwargs] * len(self.cases),
            [self.system_prompt] * len(self.cases),
            range(len(self.cases)),  # workaround: index as rank
            [self.sample_seeds] * len(self.cases),
            num_cpus=self.num_proc,
        )


if __name__ == "__main__":
    fire.Fire(Gener)
