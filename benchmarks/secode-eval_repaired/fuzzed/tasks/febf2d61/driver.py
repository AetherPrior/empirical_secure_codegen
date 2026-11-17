ATTACKS = {
    "semicolon": ["ls; whoami", "date; ls"],
    "and_chain": ["ls && whoami", "date && ls"],
    "or_chain": ["ls || whoami"],
    "pipe": ["ls | whoami", "date | whoami"],
    "subshell": ["$(whoami)", "`date`", "ls $(whoami)"],
    "newline": ["ls\nwhoami", "date\nls"],
    "background": ["ls & whoami"],
    "arguments": ["ls -la", "whoami extra"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        command = fdp.PickValueInList(["ls", "whoami", "date"])
    else:
        family = fdp.PickValueInList(sorted(ATTACKS))
        command = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            command = fdp.ConsumeUnicodeNoSurrogates(3) + command
        if fdp.ConsumeBool():
            command += fdp.ConsumeUnicodeNoSurrogates(3)

    return {"command": command}
