ATTACKS = {
    "pickle_format": ["pickle", " Pickle", "pickle ", "PICKLE"],
    "pickle_protocol4": [
        "\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04flag\x94\x8c\x07exploit\x94s."
    ],
    "pickle_protocol2": [
        "\x80\x02}q\x00X\x04\x00\x00\x00flagq\x01X\x07\x00\x00\x00exploitq\x02s."
    ],
    "pickle_protocol0": [
        "(dp0\nVflag\np1\nVexploit\np2\ns."
    ],
    "pickle_scalar": [
        "\x80\x04N.",
        "\x80\x02]q\x00."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList([
            "pickle_protocol4",
            "pickle_protocol2",
            "pickle_protocol0",
            "pickle_scalar",
        ])
        payload = fdp.PickValueInList(ATTACKS[family]).encode("latin-1")
        format_name = fdp.PickValueInList(ATTACKS["pickle_format"])

        # Pickle readers commonly accept trailing bytes; this also exercises
        # handling of small, attacker-controlled data after the serialized value.
        if fdp.ConsumeBool():
            payload += fdp.ConsumeBytes(3)

        return {"encoded_bytes": payload, "format_name": format_name}

    if fdp.ConsumeBool():
        return {
            "encoded_bytes": b"name,age\nAlice,30\n",
            "format_name": "csv",
        }

    return {
        "encoded_bytes": b'{"name":"Alice","age":30}',
        "format_name": "json",
    }
