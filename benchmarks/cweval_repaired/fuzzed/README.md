# Fuzz-derived security tests: repaired CWEval

These are the fuzz tests reported in the paper: **136 tests over 35 of the 119 tasks**, in C, C++, Go, JavaScript and
Python. The other tasks have no fuzz test.

```
tests/<task>.json        kept fuzz inputs for one task, e.g. cwe_020_0_c = benchmark/core/c/cwe_020_0_c_task.c
tasks/<task>/            what is needed to replay them
    driver.py            fuzz driver: make_input(FuzzedDataProvider, sandbox) -> function arguments
    meta.json            CWE, function name, language, ...
    <task>_test.py       the benchmark's Python wrapper, used to call compiled C/C++/Go and JavaScript code
```

Each test is `{"hex": <fuzz input>, "arguments": <decoded arguments, for reading only>, "family": [<attack techniques>]}`.

## How a generation is scored

A sample is **Correct & Secure on the fuzzed benchmark** if (1) it is Correct & Secure on the repaired benchmark
(`run_plain_vllm.py --variant repaired`), and (2) the per-CWE check (`benchmarks_fuzzing_oracle/cwe_checks.py`)
finds no violation when the generation runs on any of the task's tests. No LLM is involved.

Python generations are called directly. C, C++ and Go generations are assembled and compiled the way the benchmark
does it, and JavaScript runs under node. All of them are called through the benchmark's own Python wrapper, as the
references are. A test was kept only if the secure reference passes the check and a vulnerable reference violates it.

## Reproduce the scores

From `benchmarks_fuzzing_oracle/`:

```
python cweval_score.py --tests cweval_v1/tests --runs <file listing run dirs> --jobs 16
```

The scorer reads the fuzzing workspace `benchmarks_fuzzing/tasks/cweval` and its sandbox and environment, none of which
are committed. The files here are a copy of `cweval_v1/tests` as of the paper's scoring run, restricted to the tasks
with at least one test.

The older drop-in fuzzed test files are no longer used. They are kept in `benchmarks_fuzzing_v2/legacy_dropin/` for
the `--fuzzed` flag of `run_plain_vllm.py`.
