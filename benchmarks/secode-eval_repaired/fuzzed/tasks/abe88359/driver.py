ATTACKS = {
    "cross_configuration_signature": [
        "afae23c5b1a7d5218cabc4e62357378e",
        "9c6b74265e0e0409e4ada1aa3bdc973d",
    ],
    "truncated_signature": [
        "afae23c5",
        "9c6b7426",
    ],
    "signature_with_extra_character": [
        "afae23c5b1a7d5218cabc4e62357378ex",
        "9c6b74265e0e0409e4ada1aa3bdc973dx",
    ],
    "uppercase_signature": [
        "AFAE23C5B1A7D5218CABC4E62357378E",
        "9C6B74265E0E0409E4ADA1AA3BDC973D",
    ],
    "empty_or_whitespace_signature": [
        "",
        " ",
        "\t",
        "\n",
    ],
}


def make_input(fdp, sandbox):
    names = ["db_config.json", "app_config.yaml"]
    signatures = {
        "db_config.json": "afae23c5b1a7d5218cabc4e62357378e",
        "app_config.yaml": "9c6b74265e0e0409e4ada1aa3bdc973d",
    }

    cfg_name = fdp.PickValueInList(names)

    if not fdp.ConsumeBool():
        return {"cfg_name": cfg_name, "cfg_signature": signatures[cfg_name]}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    if technique == "cross_configuration_signature":
        other_name = "app_config.yaml" if cfg_name == "db_config.json" else "db_config.json"
        cfg_signature = ATTACKS[technique][names.index(other_name)]
    else:
        cfg_signature = fdp.PickValueInList(ATTACKS[technique])

    if technique in ("truncated_signature", "signature_with_extra_character"):
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        cfg_signature = prefix + cfg_signature + suffix

    return {"cfg_name": cfg_name, "cfg_signature": cfg_signature}
