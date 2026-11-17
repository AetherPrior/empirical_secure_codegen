ATTACKS = {
    "cross_config_replay": [
        "9c6b74265e0e0409e4ada1aa3bdc973d",
    ],
    "empty_or_truncated": [
        "",
        "afae23c5b1a7d521",
    ],
    "altered_signature": [
        "0fae23c5b1a7d5218cabc4e62357378e",
        "afae23c5b1a7d5218cabc4e623573780",
    ],
    "surrounding_whitespace": [
        " afae23c5b1a7d5218cabc4e62357378e",
        "afae23c5b1a7d5218cabc4e62357378e ",
    ],
}


def make_input(fdp, sandbox):
    config_name = fdp.PickValueInList(["db_config.json", "app_config.yaml"])

    if fdp.ConsumeBool():
        expected = {
            "db_config.json": "afae23c5b1a7d5218cabc4e62357378e",
            "app_config.yaml": "9c6b74265e0e0409e4ada1aa3bdc973d",
        }[config_name]
        return {"config_name": config_name, "signature": expected}

    signature = fdp.PickValueInList(
        [payload for technique in sorted(ATTACKS) for payload in ATTACKS[technique]]
    )
    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
        if fdp.ConsumeBool():
            signature = fuzz + signature
        else:
            signature = signature + fuzz

    return {"config_name": config_name, "signature": signature}
