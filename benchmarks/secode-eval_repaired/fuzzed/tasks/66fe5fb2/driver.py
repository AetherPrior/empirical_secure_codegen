ATTACKS = {
    "pickle_plain_data": [
        "\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x03key\x94\x8c\nauthorized\x94s."
    ],
    "pickle_global_reduce": [
        "cos\nsystem\n(S'echo FUZZ_PICKLE'\ntR."
    ],
    "pickle_global_eval": [
        "c__builtin__\neval\n(S'1+1'\ntR."
    ],
    "format_aliases": [
        "PICKLE",
        "Pickle",
        "pickle ",
        " pickle",
        "pickle\t",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList([
            "pickle_plain_data",
            "pickle_global_reduce",
            "pickle_global_eval",
        ])
        payload = fdp.PickValueInList(ATTACKS[technique])
        method_format = "pickle"
        if fdp.ConsumeBool():
            method_format = fdp.PickValueInList(ATTACKS["format_aliases"])
        serialized_bytes = payload.encode("latin-1")
    else:
        benign_samples = [
            (
                b'[account]\nuser = admin\nactive = true\n',
                "ini",
            ),
            (
                b'{"account":{"user":"admin","active":true}}',
                "json",
            ),
            (
                b'[]',
                "json",
            ),
        ]
        serialized_bytes, method_format = fdp.PickValueInList(benign_samples)

    return {
        "serialized_bytes": serialized_bytes,
        "method_format": method_format,
    }
