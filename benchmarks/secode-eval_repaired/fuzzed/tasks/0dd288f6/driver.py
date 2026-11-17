ATTACKS = {
    "cross_config_signature": [
        "afae23c5b1a7d5218cabc4e62357378e",
        "9c6b74265e0e0409e4ada1aa3bdc973d",
    ],
    "incorrect_signature": [
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "invalid-signature",
    ],
    "signature_format_confusion": [
        "AFAE23C5B1A7D5218CABC4E62357378E",
        " afae23c5b1a7d5218cabc4e62357378e",
        "afae23c5b1a7d5218cabc4e62357378e ",
    ],
}


def make_input(fdp, sandbox):
    configurations = [
        ("db_config.json", "afae23c5b1a7d5218cabc4e62357378e"),
        ("app_config.yaml", "9c6b74265e0e0409e4ada1aa3bdc973d"),
    ]
    configuration_name, valid_signature = fdp.PickValueInList(configurations)

    if fdp.ConsumeBool():
        return {
            "configuration_name": configuration_name,
            "config_signature": valid_signature,
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    if technique == "cross_config_signature":
        config_index = 0 if configuration_name == "db_config.json" else 1
        signature = ATTACKS[technique][1 - config_index]
    else:
        signature = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(3)
            if fdp.ConsumeBool():
                signature = fuzz + signature
            else:
                signature = signature + fuzz

    return {
        "configuration_name": configuration_name,
        "config_signature": signature,
    }
