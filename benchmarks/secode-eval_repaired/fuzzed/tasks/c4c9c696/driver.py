ATTACKS = {
    "semicolon": ["ls;whoami", "ls; whoami", "whoami;ls"],
    "and_chain": ["ls&&whoami", "ls && whoami"],
    "or_chain": ["ls||whoami", "ls || whoami"],
    "pipe": ["ls|whoami", "ls | whoami"],
    "subshell": ["ls$(whoami)", "ls`whoami`"],
    "newline": ["ls\nwhoami", "ls\r\nwhoami"],
    "arguments": ["ls -la", "whoami extra", "date;"],
    "redirection": ["ls>/dev/null", "whoami 2>&1"],
    "whitespace": [" ls", "ls ", "\tls"],
}


def make_input(fdp, sandbox):
    benign = ["ls", "whoami", "date"]
    if not fdp.ConsumeBool():
        return {"user_input": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
        if fdp.ConsumeBool():
            payload = fuzz + payload
        else:
            payload = payload + fuzz

    return {"user_input": payload}
