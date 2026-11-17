ATTACKS = {
    "semicolon": ["ls;whoami", "ls -la; whoami"],
    "and_chain": ["ls&&whoami", "ls && whoami"],
    "pipe": ["ls|whoami"],
    "subshell": ["$(whoami)", "`whoami`", "ls$(whoami)"],
    "newline": ["ls\nwhoami"],
    "arguments": ["ls -la", "whoami attacker", "date +%s"],
    "whitespace": [" ls", "ls ", "\tls"],
    "redirection": ["ls>out", "whoami 2>&1"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        command = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            if fdp.ConsumeBool():
                command = fuzz + command
            else:
                command += fuzz
    else:
        command = fdp.PickValueInList(["ls", "whoami", "date"])

    return {"command": command}
