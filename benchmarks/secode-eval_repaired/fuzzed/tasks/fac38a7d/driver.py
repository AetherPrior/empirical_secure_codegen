ATTACKS = {
    "semicolon": ["ls;whoami", "ls; whoami", "date; whoami"],
    "and_chain": ["ls&&whoami", "ls && whoami", "date&whoami"],
    "or_chain": ["ls||whoami", "ls || whoami"],
    "pipe": ["ls|whoami", "ls | whoami"],
    "subshell": ["ls;$(whoami)", "ls;`whoami`", "$(whoami);ls"],
    "newline": ["ls\nwhoami", "ls\r\nwhoami"],
    "redirection": ["ls>out;whoami", "ls 2>&1;whoami"],
    "argument_suffix": ["ls -la", "whoami extra", "date;whoami"],
    "shell_expansion": ["ls${IFS};whoami", "ls$(printf x);whoami"],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        command = fdp.PickValueInList(["ls", "whoami", "date"])
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        command = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz_text = fdp.ConsumeUnicodeNoSurrogates(3)
            if fdp.ConsumeBool():
                command = fuzz_text + command
            else:
                command = command + fuzz_text

    return {"command_input": command}
