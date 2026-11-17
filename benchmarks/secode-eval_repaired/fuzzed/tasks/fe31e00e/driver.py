ATTACKS = {
    "pickle_primitive": [
        "80044b2a2e",  # Protocol 4 pickle of integer 42
    ],
    "pickle_object": [
        "80049517000000000000007d948c036b6579948c0a756e617574686f72697a656494732e",
    ],
    "pickle_reduce_eval": [
        "636275696c74696e730a6576616c0a285327312b312774522e",
    ],
    "malformed_pickle": [
        "80044b",
        "80049500000000000000002e",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        # Benign JSON and INI samples are deliberately kept outside ATTACKS.
        samples = [
            (b'{"account":{"user":"admin","active":true}}', "json"),
            (b"[account]\nuser = admin\nactive = true\n", "ini"),
            (b"[]", "json"),
            (b"[x]\na = 1\n", "ini"),
        ]
        byte_data, serialization_format = fdp.PickValueInList(samples)
        return {
            "byte_data": byte_data,
            "serialization_format": serialization_format,
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload_hex = fdp.PickValueInList(ATTACKS[technique])
    byte_data = bytes.fromhex(payload_hex)

    serialization_format = fdp.PickValueInList(
        ["pickle", "pickle", "json", "ini", "PICKLE", " Pickle"]
    )
    return {
        "byte_data": byte_data,
        "serialization_format": serialization_format,
    }
