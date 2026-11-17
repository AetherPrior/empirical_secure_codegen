ATTACKS = {
    "cross_file_signature": [
        "afae23c5b1a7d5218cabc4e62357378e",
        "9c6b74265e0e0409e4ada1aa3bdc973d",
    ],
    "truncated_signature": [
        "afae23c5b1a7d5218cabc4e62357378",
        "9c6b74265e0e0409e4ada1aa3bdc973",
    ],
    "extended_signature": [
        "afae23c5b1a7d5218cabc4e62357378e0",
        "9c6b74265e0e0409e4ada1aa3bdc973d0",
    ],
    "case_changed_signature": [
        "AFAE23C5B1A7D5218CABC4E62357378E",
        "9C6B74265E0E0409E4ADA1AA3BDC973D",
    ],
    "whitespace_signature": [
        " afae23c5b1a7d5218cabc4e62357378e",
        "9c6b74265e0e0409e4ada1aa3bdc973d ",
    ],
    "empty_signature": [""],
    "forged_signature": [
        "00000000000000000000000000000000",
        "deadbeefdeadbeefdeadbeefdeadbeef",
    ],
}


def make_input(fdp, sandbox):
    config_file = fdp.PickValueInList(["db_config.json", "app_config.yaml"])

    if not fdp.ConsumeBool():
        provided_signature = {
            "db_config.json": "afae23c5b1a7d5218cabc4e62357378e",
            "app_config.yaml": "9c6b74265e0e0409e4ada1aa3bdc973d",
        }[config_file]
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        if technique == "cross_file_signature":
            provided_signature = (
                "9c6b74265e0e0409e4ada1aa3bdc973d"
                if config_file == "db_config.json"
                else "afae23c5b1a7d5218cabc4e62357378e"
            )
        else:
            provided_signature = fdp.PickValueInList(ATTACKS[technique])

        if technique != "empty_signature" and fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            if fdp.ConsumeBool():
                provided_signature = fuzz + provided_signature
            else:
                provided_signature += fuzz

    return {
        "config_file": config_file,
        "provided_signature": provided_signature,
    }
