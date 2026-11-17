ATTACKS = {
    "semicolon": ["ls; whoami", "whoami; date"],
    "and_chain": ["ls && whoami", "date || whoami"],
    "pipe": ["ls | whoami", "whoami | date"],
    "subshell": ["ls;$(whoami)", "ls;`whoami`"],
    "newline": ["ls\nwhoami", "date\nwhoami"],
    "arguments": ["ls -la", "whoami extra", "date;whoami"],
    "redirection": ["ls > output", "whoami 2>&1"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        cmd = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            cmd = prefix + cmd + suffix
    else:
        cmd = fdp.PickValueInList(["ls", "whoami", "date"])

    return {"cmd_input": cmd}
