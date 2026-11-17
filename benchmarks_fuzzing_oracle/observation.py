"""What one call of a function did. The CWE checks look only at this, never at the reference's output."""
import copy
import os
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Observation:
    returned: Any = None              # the return value
    raised: Optional[str] = None      # name of the exception raised, or None
    timed_out: bool = False
    commands: list = field(default_factory=list)      # recorded (never executed) command / network calls:
                                                      #   (sink name, args, kwargs)
    files_written: dict = field(default_factory=dict)  # sandbox path -> content
    state_before: dict = field(default_factory=dict)   # copies of the task's global data before the call
    state_after: dict = field(default_factory=dict)    # ... and after it


@dataclass
class Task:
    cwe: str
    setup_globals: dict               # the globals from the task's setup code (the prompt shows these)
    sandbox: str = ""


def observe(function, arguments, setup_globals, sandbox="", recorder=None, timeout_error=TimeoutError):
    """Call function(**arguments) once and record what it did.

    recorder: the fuzzing harness's sink recorder (harness.REC), which records command and network calls instead of
              running them.
    timeout_error: the exception the harness's per-call alarm raises.
    """
    result = Observation()
    result.state_before = copy_of_data(setup_globals)
    files_before = read_files(sandbox)
    if recorder is not None:
        recorder.reset()

    try:
        result.returned = function(**arguments)
    except timeout_error:
        result.timed_out = True
    except BaseException as error:  # noqa: BLE001  (we record every kind of failure)
        result.raised = type(error).__name__

    if recorder is not None:
        result.commands = list(recorder.calls)
    result.state_after = copy_of_data(setup_globals)
    files_after = read_files(sandbox)
    result.files_written = {path: data for path, data in files_after.items() if files_before.get(path) != data}
    return result


def copy_of_data(setup_globals):
    """Copies of the global variables that hold data (not functions or modules)."""
    data = {}
    for name, value in setup_globals.items():
        if name.startswith("__") or callable(value) or type(value).__name__ == "module":
            continue
        try:
            data[name] = copy.deepcopy(value)
        except Exception:
            data[name] = repr(value)
    return data


def read_files(sandbox):
    files = {}
    if not sandbox or not os.path.isdir(sandbox):
        return files
    for folder, _subfolders, names in os.walk(sandbox):
        for name in names:
            path = os.path.join(folder, name)
            try:
                with open(path, "rb") as f:
                    files[os.path.relpath(path, sandbox)] = f.read(65536)
            except OSError:
                files[os.path.relpath(path, sandbox)] = b""
    return files
