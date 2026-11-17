ATTACKS = {
    "other_config_signature": [
        "afae23c5b1a7d5218cabc4e62357378e",
        "9c6b74265e0e0409e4ada1aa3bdc973d",
    ],
    "truncated_signature": [
        "afae23c5b1a7d5218cabc4e6235737",
        "9c6b74265e0e0409e4ada1aa3bdc973",
    ],
    "signature_format_variants": [
        "AFAE23C5B1A7D5218CABC4E62357378E",
        " 9c6b74265e0e0409e4ada1aa3bdc973d",
        "afae23c5b1a7d5218cabc4e62357378e ",
    ],
    "untrusted_signature": [
        "",
        "00000000000000000000000000000000",
    ],
}

def make_input(fdp, sandbox):
    filenames = ["db_config.json", "app_config.yaml"]
    expected = {
        "db_config.json": "afae23c5b1a7d5218cabc4e62357378e",
        "app_config.yaml": "9c6b74265e0e0409e4ada1aa3bdc973d",
    }

    filename = fdp.PickValueInList(filenames)

    if not fdp.ConsumeBool():
        return {
            "config_filename": filename,
            "provided_sig": expected[filename],
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    if technique == "other_config_signature":
        # Each payload is valid for the other filename, not this one.
        filename = filenames[1 - filenames.index(filename)]
        signature = expected[filenames[1 - filenames.index(filename)]]
    else:
        signature = fdp.PickValueInList(ATTACKS[technique])

    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
        if fdp.ConsumeBool():
            signature = fuzz + signature
        else:
            signature = signature + fuzz

    return {"config_filename": filename, "provided_sig": signature}
