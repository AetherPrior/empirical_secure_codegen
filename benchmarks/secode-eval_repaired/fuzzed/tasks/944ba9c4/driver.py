ATTACKS = {
    "other_config_signature": [
        "afae23c5b1a7d5218cabc4e62357378e",
        "9c6b74265e0e0409e4ada1aa3bdc973d",
    ],
    "truncated_signature": [
        "afae23c5b1a7d521",
        "9c6b74265e0e0409",
    ],
    "modified_signature": [
        "afae23c5b1a7d5218cabc4e62357378e0",
        "x9c6b74265e0e0409e4ada1aa3bdc973d",
    ],
    "empty_signature": [""],
}

def make_input(fdp, sandbox):
    filenames = ["db_config.json", "app_config.yaml"]
    expected = {
        "db_config.json": "afae23c5b1a7d5218cabc4e62357378e",
        "app_config.yaml": "9c6b74265e0e0409e4ada1aa3bdc973d",
    }

    filename = fdp.PickValueInList(filenames)

    if fdp.ConsumeBool():
        signature = expected[filename]
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if technique == "other_config_signature":
            other_filename = (
                "app_config.yaml" if filename == "db_config.json"
                else "db_config.json"
            )
            signature = expected[other_filename]
        else:
            signature = payload

    return {
        "filename": filename,
        "cryptographic_signature": signature,
    }
