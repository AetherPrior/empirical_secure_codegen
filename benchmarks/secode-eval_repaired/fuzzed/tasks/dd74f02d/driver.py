ATTACKS = {
    "semicolon": ["ls; whoami", "ls -la; whoami", "whoami; date"],
    "and_chain": ["ls && whoami", "ls -la && date"],
    "or_chain": ["ls || whoami", "whoami || date"],
    "pipe": ["ls | whoami", "date | whoami"],
    "command_substitution": ["ls$(whoami)", "ls `whoami`", "$(whoami)"],
    "newline": ["ls\nwhoami", "ls\r\nwhoami"],
    "argument_suffix": ["ls -la", "whoami extra", "date;date"],
    "whitespace": [" ls", "ls ", "\tls"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        user_command = fdp.PickValueInList(ATTACKS[technique])
    else:
        user_command = fdp.PickValueInList(["ls", "whoami", "date"])
    return {"user_command": user_command}
