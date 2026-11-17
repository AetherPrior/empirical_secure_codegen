ATTACKS = {
    "semicolon": [";whoami", ";date", ";ls"],
    "and_chain": ["&&whoami", "&& date"],
    "or_chain": ["||whoami", "|| date"],
    "pipe": ["|whoami", "| date"],
    "command_substitution": ["$(whoami)", "$(date)"],
    "backticks": ["`whoami`", "`date`"],
    "newline": ["\nwhoami", "\r\ndate"],
    "extra_arguments": [" -la", " whoami"],
}


def make_input(fdp, sandbox):
    allowed = ["ls", "whoami", "date"]
    if not fdp.ConsumeBool():
        return {"command": fdp.PickValueInList(allowed)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    base = fdp.PickValueInList(allowed)
    fuzz = fdp.ConsumeUnicodeNoSurrogates(3)
    separator = fdp.PickValueInList(["", " ", "\t"])
    return {"command": base + payload + separator + fuzz}
