ATTACKS = {
    "semicolon": ["ls;whoami", "whoami;date", "date;ls"],
    "and_chain": ["ls&&whoami", "ls||whoami"],
    "pipe": ["ls|whoami", "whoami|date"],
    "subshell": ["$(whoami)", "`whoami`", "ls $(date)"],
    "newline": ["ls\nwhoami", "whoami\ndate"],
    "background": ["ls&whoami"],
    "arguments": ["ls -la", "whoami extra"],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        return {"usr_cmd": fdp.PickValueInList(["ls", "whoami", "date"])}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    if fdp.ConsumeBool():
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        payload = prefix + payload + suffix
    return {"usr_cmd": payload}
