ATTACKS = {
    "pickle_protocol4": [
        "\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00]\x94(K\x01K\x02K\x03e.",
    ],
    "pickle_protocol0": [
        "(lp0\nI1\naI2\na.",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        return {
            "input_data": payload.encode("latin-1"),
            "serialization_format": "pickle",
        }

    value = fdp.ConsumeIntInRange(0, 100)
    if fdp.ConsumeBool():
        return {
            "input_data": ("[" + str(value) + ", 2, 3]").encode("ascii"),
            "serialization_format": "json",
        }
    return {
        "input_data": (
            "<root><value>" + str(value) + "</value></root>"
        ).encode("ascii"),
        "serialization_format": "xml",
    }
