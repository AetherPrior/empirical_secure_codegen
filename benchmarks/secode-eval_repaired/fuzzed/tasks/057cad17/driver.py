ATTACKS = {
    "cross_file_signature": ["9c6b74265e0e0409e4ada1aa3bdc973d"],
    "empty_signature": [""],
    "truncated_signature": ["afae23c5b1a7d5218cabc4e6235737"],
    "extended_signature": ["afae23c5b1a7d5218cabc4e62357378e0"],
    "case_changed_signature": ["AFAE23C5B1A7D5218CABC4E62357378E"],
    "whitespace_wrapped_signature": [" afae23c5b1a7d5218cabc4e62357378e "],
    "unrelated_signature": ["00000000000000000000000000000000"],
}


def make_input(fdp, sandbox):
    filenames = ["db_config.json", "app_config.yaml"]

    if fdp.ConsumeBool():
        filename = fdp.PickValueInList(filenames)
        sig = (
            "afae23c5b1a7d5218cabc4e62357378e"
            if filename == "db_config.json"
            else "9c6b74265e0e0409e4ada1aa3bdc973d"
        )
        return {"filename": filename, "sig": sig}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    sig = fdp.PickValueInList(ATTACKS[technique])

    if technique == "cross_file_signature":
        filename = "db_config.json"
    else:
        filename = fdp.PickValueInList(filenames)

    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
        if fdp.ConsumeBool():
            sig = fuzz + sig
        else:
            sig = sig + fuzz

    return {"filename": filename, "sig": sig}
