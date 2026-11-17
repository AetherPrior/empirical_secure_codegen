import os

ATTACKS = {
    "semicolon": ["; printf INJECTED"],
    "and_chain": [" && printf INJECTED"],
    "pipe": [" | printf INJECTED"],
    "subshell": ["; (printf INJECTED)"],
}


def make_input(fdp, sandbox):
    target_dir = os.path.join(sandbox, "target")
    os.makedirs(target_dir, exist_ok=True)
    with open(os.path.join(target_dir, "sample.txt"), "w", encoding="utf-8") as f:
        f.write("sample\n")

    benign_paths = [
        target_dir,
        sandbox,
        os.path.join(sandbox, "sample.txt"),
        os.path.join(sandbox, "missing"),
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(6)
        noise = "".join(
            c for c in fuzz
            if c.isascii() and (c.isalnum() or c in "._-")
        )
        if noise:
            noise = "f" + noise
            dir_path = target_dir + " " + noise + payload
        else:
            dir_path = target_dir + payload
    else:
        dir_path = fdp.PickValueInList(benign_paths)

    return {"dir_path": dir_path}
