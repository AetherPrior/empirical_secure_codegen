ATTACKS = {
    "pickle_protocol0": [
        "(dp0\nVkey\np1\nVauthorized\np2\ns."
    ],
    "pickle_protocol2": [
        "\x80\x02}q\x00X\x03\x00\x00\x00keyq\x01X\n\x00\x00\x00authorizedq\x02s."
    ],
    "pickle_protocol4": [
        "\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x03key\x94\x8c\nauthorized\x94s."
    ],
    "forbidden_format": [
        "pickle"
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        techniques = ["pickle_protocol0", "pickle_protocol2", "pickle_protocol4"]
        technique = fdp.PickValueInList(techniques)
        byte_sequence = fdp.PickValueInList(ATTACKS[technique]).encode("latin-1")
        if fdp.ConsumeBool():
            # Pickle stops at STOP, so trailing bytes preserve the valid payload.
            byte_sequence += fdp.ConsumeBytes(4)
        data_format = fdp.PickValueInList(ATTACKS["forbidden_format"])
    else:
        benign_samples = [
            ("json", b'{"user":"admin","active":true}'),
            ("ini", b"[account]\nuser = admin\nactive = true\n"),
            ("json", b'{"items":[1,2,3]}'),
            ("ini", b"[settings]\nmode = safe\n"),
        ]
        data_format, byte_sequence = fdp.PickValueInList(benign_samples)

    return {"byte_sequence": byte_sequence, "data_format": data_format}
