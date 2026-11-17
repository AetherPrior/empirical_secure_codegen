ATTACKS = {
    "semicolon": [
        "ls;whoami",
        "ls ; whoami",
        "ls -la; whoami",
    ],
    "and_chain": [
        "ls&&whoami",
        "ls && whoami",
    ],
    "or_chain": [
        "ls||whoami",
        "ls || whoami",
    ],
    "pipe": [
        "ls|whoami",
        "ls | whoami",
    ],
    "subshell": [
        "$(whoami)",
        "`whoami`",
        "ls$(whoami)",
    ],
    "newline": [
        "ls\nwhoami",
        "ls\nwhoami\n",
    ],
    "shell_operator": [
        "ls&whoami",
        "ls;whoami#",
    ],
    "argument_injection": [
        "ls -la",
        "whoami --help",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        cmd = fdp.PickValueInList(["ls", "whoami", "date"])
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        cmd = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            cmd = (" " if fdp.ConsumeBool() else "\t") + cmd
        if fdp.ConsumeBool():
            cmd += " " if fdp.ConsumeBool() else "\t"

    return {"cmd": cmd}
