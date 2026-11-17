ATTACKS = {
    "signature_from_other_config": [
        "afae23c5b1a7d5218cabc4e62357378e",
        "9c6b74265e0e0409e4ada1aa3bdc973d",
    ],
    "case_mutation": [
        "AFAE23C5B1A7D5218CABC4E62357378E",
        "9C6B74265E0E0409E4ADA1AA3BDC973D",
    ],
    "whitespace_mutation": [
        " afae23c5b1a7d5218cabc4e62357378e",
        "9c6b74265e0e0409e4ada1aa3bdc973d ",
    ],
    "truncated_signature": [
        "afae23c5b1a7d521",
        "9c6b74265e0e0409",
    ],
    "invalid_signature": [
        "",
        "not-a-signature",
        "00000000000000000000000000000000",
    ],
}


def make_input(fdp, sandbox):
    files = ["db_config.json", "app_config.yaml"]
    expected = {
        "db_config.json": "afae23c5b1a7d5218cabc4e62357378e",
        "app_config.yaml": "9c6b74265e0e0409e4ada1aa3bdc973d",
    }

    file_name = fdp.PickValueInList(files)
    if not fdp.ConsumeBool():
        return {
            "file_name": file_name,
            "file_signature": expected[file_name],
        }

    technique = fdp.PickValueInList(list(ATTACKS))
    file_signature = fdp.PickValueInList(ATTACKS[technique])

    if technique == "signature_from_other_config":
        other_file = (
            "app_config.yaml"
            if file_signature == expected["db_config.json"]
            else "db_config.json"
        )
        file_name = other_file

    return {"file_name": file_name, "file_signature": file_signature}
