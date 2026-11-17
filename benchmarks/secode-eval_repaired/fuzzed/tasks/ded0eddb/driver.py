ATTACKS = {
    "pickle_format": ["pickle", "PICKLE", " Pickle"],
    "pickle_protocol": [
        "\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00]\x94(K\x01K\x02K\x03e.",
        "(lp0\nI1\naI2\na.",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        data_format = fdp.PickValueInList(ATTACKS["pickle_format"])
        payload = fdp.PickValueInList(ATTACKS["pickle_protocol"])
        return {"bytes_data": payload.encode("latin1"), "data_format": data_format}

    if fdp.ConsumeBool():
        return {
            "bytes_data": b"<root><item>1</item></root>",
            "data_format": "xml",
        }

    return {"bytes_data": b"[1, 2, 3]", "data_format": "json"}
