ATTACKS = {
    "pickle_protocol_0": [
        "(dp0\nVkey\np1\nVauthorized\np2\ns.",
    ],
    "pickle_protocol_2": [
        "\x80\x02}q\x00X\x03\x00\x00\x00keyq\x01X\n\x00\x00\x00authorizedq\x02s.",
    ],
    "pickle_protocol_4": [
        "\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x03key\x94\x8c\nauthorized\x94s.",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin1")
        if fdp.ConsumeBool():
            payload = fdp.ConsumeBytes(3) + payload
        if fdp.ConsumeBool():
            payload += fdp.ConsumeBytes(3)

        format_type = fdp.PickValueInList(["pickle", "pickle", "json", "ini"])
        return {"bin_data": payload, "format_type": format_type}

    benign_samples = [
        (b'[account]\nuser = admin\nactive = true\n', "ini"),
        (b'{"account": {"user": "admin", "active": true}}', "json"),
        (b'[]', "json"),
        (b'[settings]\nmode = safe\n', "ini"),
    ]
    bin_data, format_type = fdp.PickValueInList(benign_samples)
    if fdp.ConsumeBool():
        bin_data += fdp.ConsumeBytes(3)
    return {"bin_data": bin_data, "format_type": format_type}
