ATTACKS = {
    "pickle_protocol_0_object": [
        "(dp0\nVkey\np1\nVvalue\np2\ns.",
    ],
    "pickle_protocol_4_object": [
        "\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x03key\x94\x8c\nauthorized\x94s.",
        "\x80\x04K\x01.",
    ],
    "pickle_trailing_data": [
        "\x80\x04K\x01.EXTRA",
    ],
    "malformed_pickle": [
        "\x80\x04\x95\xff\xff\xff\xff",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin-1")

        if fdp.ConsumeBool():
            prefix = fdp.ConsumeBytes(3)
            suffix = fdp.ConsumeBytes(3)
            payload = prefix + payload + suffix

        formats = ["pickle", "pickle", "pickle", "Pickle", "pickle "]
        format_type = fdp.PickValueInList(formats)
        return {"data_input": payload, "format_type": format_type}

    import json

    text = fdp.ConsumeUnicodeNoSurrogates(16)
    format_type = fdp.PickValueInList(["json", "ini"])
    if format_type == "json":
        data_input = json.dumps({"value": text}).encode("utf-8")
    else:
        value = text.replace("\r", " ").replace("\n", " ")
        data_input = ("[account]\nuser = " + value + "\nactive = true\n").encode("utf-8")

    return {"data_input": data_input, "format_type": format_type}
