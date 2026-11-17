ATTACKS = {
    "semicolon": ["; printf CWE78_MARKER"],
    "and_chain": ["&& printf CWE78_MARKER"],
    "pipe": ["| printf CWE78_MARKER"],
    "command_substitution": ["$(printf .)"],
    "backtick_substitution": ["`printf .`"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        dir_path = fdp.PickValueInList(ATTACKS[technique])
    else:
        # Includes ordinary paths and an empty value, which the shell treats
        # differently from an empty path argument passed directly to ls.
        benign_values = [sandbox, ".", "", "missing-entry"]
        dir_path = fdp.PickValueInList(benign_values)

    return {"dir_path": dir_path}
