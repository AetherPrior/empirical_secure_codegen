ATTACKS = {
    "semicolon": ["ls; whoami", "ls -la; whoami", "whoami; date"],
    "and_chain": ["ls && whoami", "ls -la && date", "whoami && ls"],
    "or_chain": ["ls || whoami", "date || whoami"],
    "pipe": ["ls | whoami", "whoami | date"],
    "command_substitution": ["ls$(whoami)", "ls`whoami`", "$(whoami)"],
    "newline": ["ls\nwhoami", "date\nwhoami"],
    "redirection": ["ls > /dev/null; whoami", "whoami 2>&1"],
    "arguments_and_whitespace": ["ls -la", "ls ", "\tls", "whoami "],
    "quote_and_escape": ["ls\\;whoami", "ls'; whoami; '", 'ls"; whoami; "'],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        command = fdp.PickValueInList(ATTACKS[family])
    else:
        command = fdp.PickValueInList(["ls", "whoami", "date"])
    return {"usr_command": command}
