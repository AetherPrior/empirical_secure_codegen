"""Run implementations on fuzz inputs and judge each run with the CWE check. Runs inside the sandbox (sandbox.sh).

usage: oracle_replay.py <task_dir> --inputs <jsonl with "hex"> --impl name=path.py [--impl ...]

For every input and implementation it prints whether the CWE's property was violated (True / False / None).
Each run starts from a fresh copy of the module's data, so one input cannot affect the next.
Task facts (allow-lists, tokens, limits) come only from the task's setup code (oracle_setup.py), never from the
implementation, so a generation cannot change them by defining its own globals.
"""
import argparse
import copy
import importlib.util
import json
import os
import shutil
import signal
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "benchmarks_fuzzing"))
import harness                               # noqa: E402  (sink recorder, per-call timeout)
from cwe_checks import judge, url_host       # noqa: E402
from observation import Task, observe        # noqa: E402


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def setup_facts(task_dir):
    facts = {}
    setup = task_dir / "oracle_setup.py"
    if setup.exists():
        try:
            exec(compile(setup.read_text(), str(setup), "exec"), facts)
        except Exception:
            pass
    return {k: v for k, v in facts.items() if not k.startswith("__")}


def run_one(module, function_name, driver, data, task):
    """Build the arguments from the fuzz bytes, call the function once, judge the call."""
    from atheris import FuzzedDataProvider
    sandbox = tempfile.mkdtemp()
    old_cwd = os.getcwd()
    os.chdir(sandbox)
    saved = {}
    for name, value in vars(module).items():
        if not name.startswith("__") and not callable(value) and type(value).__name__ != "module":
            try:
                saved[name] = copy.deepcopy(value)
            except Exception:
                pass
    try:
        try:
            arguments = driver.make_input(FuzzedDataProvider(data), sandbox)
        except Exception:
            return None, None
        signal.signal(signal.SIGALRM, harness._alarm)
        signal.setitimer(signal.ITIMER_REAL, harness.PER_CALL_TIMEOUT)
        try:
            result = observe(getattr(module, function_name), arguments, vars(module), sandbox,
                             recorder=harness.REC, timeout_error=harness._Timeout)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        task.sandbox = sandbox
        names = task.setup_globals.get("ORACLE_BASE_URL_ARGS", []) if not task.from_arguments else []
        task.base_hosts = {url_host(arguments[n]) for n in names if isinstance(arguments.get(n), str)} - {None}
        if task.from_arguments:       # CWEval states its facts (allowed domain, base folder) as arguments
            task.setup_globals = {k: v for k, v in arguments.items() if isinstance(v, (str, list, tuple, set, dict, int))}
        return harness._short(arguments, 300), judge(task.cwe, arguments, result, task)
    finally:
        vars(module).update(saved)            # fresh data for the next input
        os.chdir(old_cwd)
        shutil.rmtree(sandbox, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("task_dir")
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--impl", action="append", default=[], help="name=path.py")
    args = parser.parse_args()

    task_dir = Path(args.task_dir).resolve()
    meta = json.loads((task_dir / "meta.json").read_text())
    sys.path.insert(0, str(task_dir))
    if not meta.get("native"):      # native tasks (CWEval C/C++/Go/JS) must really run their binary
        harness.install_sinks()
    driver = importlib.import_module("driver")
    task = Task(str(meta["cwe"]), setup_facts(task_dir))
    task.from_arguments = not (task_dir / "oracle_setup.py").exists()

    modules, broken = {}, {}
    for spec in args.impl:
        name, path = spec.split("=", 1)
        try:
            modules[name] = load_module("impl_" + name, path)
            getattr(modules[name], meta["fn"])
        except BaseException as error:  # noqa: BLE001
            broken[name] = type(error).__name__
            modules.pop(name, None)

    rows = []
    for line in open(args.inputs):
        if not line.strip():
            continue
        data = bytes.fromhex(json.loads(line)["hex"])
        row = {"hex": data.hex(), "violated": {}}
        for name, module in modules.items():
            shown, verdict = run_one(module, meta["fn"], driver, data, task)
            row["violated"][name] = verdict
            row.setdefault("arguments", shown)
        rows.append(row)
    print(json.dumps({"broken": broken, "rows": rows}))


if __name__ == "__main__":
    main()
