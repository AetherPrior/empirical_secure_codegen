ATTACKS = {
    "pickle_protocol4_mapping": [
        "\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x03key\x94\x8c\nauthorized\x94s."
    ],
    "pickle_protocol2_mapping": [
        "\x80\x02}q\x00X\x03\x00\x00\x00keyq\x01X\n\x00\x00\x00authorizedq\x02s."
    ],
    "pickle_protocol0_mapping": [
        "(dp0\nS'key'\np1\nS'authorized'\np2\ns."
    ],
    "pickle_protocol4_scalar": [
        "\x80\x04K\x01."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        return {
            "serialized_input": payload.encode("latin-1"),
            "serialization_format": "pickle",
        }

    import json

    if fdp.ConsumeBool():
        value = fdp.PickValueInList(["admin", "guest", "user"])
        serialized = json.dumps({"account": value}).encode("utf-8")
        return {"serialized_input": serialized, "serialization_format": "json"}

    serialized = fdp.PickValueInList([
        b"[account]\nuser = admin\nactive = true\n",
        b"[settings]\nmode = safe\n",
    ])
    return {"serialized_input": serialized, "serialization_format": "ini"}
