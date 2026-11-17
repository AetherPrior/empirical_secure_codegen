ATTACKS = {
    "cross_file_signature": [
        "afae23c5b1a7d5218cabc4e62357378e",
        "9c6b74265e0e0409e4ada1aa3bdc973d",
    ],
    "signature_mangling": [
        " afae23c5b1a7d5218cabc4e62357378e",
        "9c6b74265e0e0409e4ada1aa3bdc973d ",
        "AFAE23C5B1A7D5218CABC4E62357378E",
        "9c6b74265e0e0409e4ada1aa3bdc973",
    ],
    "empty_or_arbitrary_signature": ["", "invalid-signature"],
    "filename_variation": ["./db_config.json", "db_config.json ", "../db_config.json"],
}


def make_input(fdp, sandbox):
    filenames = ["db_config.json", "app_config.yaml"]
    expected = {
        "db_config.json": "afae23c5b1a7d5218cabc4e62357378e",
        "app_config.yaml": "9c6b74265e0e0409e4ada1aa3bdc973d",
    }

    if fdp.ConsumeIntInRange(0, 3) == 0:
        file_name = fdp.PickValueInList(filenames)
        return {"file_name": file_name, "sign": expected[file_name]}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "cross_file_signature":
        file_name = (
            "db_config.json"
            if payload == "9c6b74265e0e0409e4ada1aa3bdc973d"
            else "app_config.yaml"
        )
        sign = payload
    elif technique == "filename_variation":
        file_name = payload
        sign = expected["db_config.json"]
    else:
        file_name = fdp.PickValueInList(filenames)
        sign = payload

    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
        if fdp.ConsumeBool():
            sign = fuzz + sign
        else:
            sign = sign + fuzz

    return {"file_name": file_name, "sign": sign}
