ATTACKS = {
    "pickle_protocol_4": [
        "\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04flag\x94\x8c\x07exploit\x94s.",
        "\x80\x04]\x94( K\x01K\x02e.",
    ],
    "pickle_protocol_0": [
        "} (S'flag'\nS'exploit'\ns.".replace(" ", ""),
        "cbuiltins\nlen\n(S'abc'\ntR.",
    ],
    "pickle_reduce_callable": [
        "\x80\x02cbuiltins\nlen\nq\x00X\x03\x00\x00\x00abcq\x01\x85q\x02R.",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        format_type = fdp.PickValueInList(["pickle", "pickle", " pickle", "PICKLE"])
        return {"raw_data": payload.encode("latin-1"), "format_type": format_type}

    if fdp.ConsumeBool():
        return {
            "raw_data": b"name,age\nAlice,30\n",
            "format_type": "csv",
        }

    return {
        "raw_data": b'{"name":"Alice","age":30}',
        "format_type": "json",
    }
