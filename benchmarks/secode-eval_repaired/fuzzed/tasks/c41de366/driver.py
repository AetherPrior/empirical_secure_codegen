ATTACKS = {
    "cross_config_signature": ["9c6b74265e0e0409e4ada1aa3bdc973d"],
    "truncated_signature": ["afae23c5b1a7d5218cabc4e62357378"],
    "case_altered_signature": ["AFAE23C5B1A7D5218CABC4E62357378E"],
    "whitespace_wrapping": [
        " afae23c5b1a7d5218cabc4e62357378e",
        "afae23c5b1a7d5218cabc4e62357378e ",
    ],
    "signature_prefix": ["0xafae23c5b1a7d5218cabc4e62357378e"],
}


def make_input(fdp, sandbox):
    benign = [
        ("db_config.json", "afae23c5b1a7d5218cabc4e62357378e"),
        ("app_config.yaml", "9c6b74265e0e0409e4ada1aa3bdc973d"),
    ]

    if fdp.ConsumeBool():
        config_filename, crypt_signature = fdp.PickValueInList(benign)
    else:
        # These payloads target the database config, so they are all invalid
        # signatures for this supported filename.
        config_filename = "db_config.json"
        technique = fdp.PickValueInList(sorted(ATTACKS))
        crypt_signature = fdp.PickValueInList(ATTACKS[technique])

        if fdp.ConsumeBool():
            crypt_signature = (
                fdp.ConsumeUnicodeNoSurrogates(2)
                + crypt_signature
                + fdp.ConsumeUnicodeNoSurrogates(2)
            )

    return {
        "config_filename": config_filename,
        "crypt_signature": crypt_signature,
    }
