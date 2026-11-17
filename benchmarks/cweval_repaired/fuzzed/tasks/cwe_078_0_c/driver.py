import os
import string

ATTACKS = {
    "semicolon": ["; printf CWE78"],
    "and_chain": ["&& printf CWE78"],
    "pipe": ["| printf CWE78"],
    "subshell": ["; (printf CWE78)"],
    "newline": ["\nprintf CWE78"],
}


def make_input(fdp, sandbox):
    os.makedirs(sandbox, exist_ok=True)
    target = os.path.join(sandbox, "d")
    os.makedirs(target, exist_ok=True)
    with open(os.path.join(target, "sample.txt"), "w", encoding="utf-8") as f:
        f.write("sample\n")

    if fdp.ConsumeBool():
        benign_paths = [
            sandbox,
            target,
            os.path.join(target, "sample.txt"),
        ]
        return {"dir_path": fdp.PickValueInList(benign_paths)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    # Use fuzz text as part of a real directory path before the shell payload.
    raw = fdp.ConsumeUnicodeNoSurrogates(4)
    token = "".join(c if c in string.ascii_letters + string.digits else "x" for c in raw)
    fuzzed_dir = os.path.join(sandbox, "d" + token)
    os.makedirs(fuzzed_dir, exist_ok=True)

    return {"dir_path": fuzzed_dir + payload}
