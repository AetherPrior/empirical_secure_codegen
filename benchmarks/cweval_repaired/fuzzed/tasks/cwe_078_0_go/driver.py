ATTACKS = {
    "semicolon": ["; printf CWE78_MARKER #"],
    "and_chain": ["&& printf CWE78_MARKER #"],
    "pipe": ["| printf CWE78_MARKER #"],
    "subshell": ["; (printf CWE78_MARKER) #"],
}


def make_input(fdp, sandbox):
    import os

    ordinary = os.path.join(sandbox, "ordinary")
    os.makedirs(ordinary, exist_ok=True)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        fuzz = "".join(
            c for c in fuzz if c.isascii() and (c.isalnum() or c in "._-")
        )
        return {"dir_path": sandbox + payload + fuzz}

    return {"dir_path": fdp.PickValueInList([sandbox, ordinary])}
