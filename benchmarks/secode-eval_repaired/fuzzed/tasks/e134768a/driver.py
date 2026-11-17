ATTACKS = {
    "pickle_protocol4": [
        "\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x03key\x94\x8c\nauthorized\x94s."
    ],
    "pickle_protocol0": [
        "(dp0\nVrole\np1\nVadmin\np2\ns."
    ],
    "forbidden_format": [
        "pickle"
    ],
}


def make_input(fdp, sandbox):
    import json

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(
            ["pickle_protocol0", "pickle_protocol4"]
        )
        payload = fdp.PickValueInList(ATTACKS[family]).encode("latin1")
        if fdp.ConsumeBool():
            extra = fdp.ConsumeBytes(4)
            payload = extra + payload if fdp.ConsumeBool() else payload + extra
        return {
            "byte_data": payload,
            "struct_format": fdp.PickValueInList(ATTACKS["forbidden_format"]),
        }

    text = fdp.ConsumeUnicodeNoSurrogates(12)
    if fdp.ConsumeBool():
        byte_data = json.dumps({"value": text}).encode("utf-8")
        struct_format = "json"
    else:
        byte_data = ("[account]\nuser = " + text + "\nactive = true\n").encode("utf-8")
        struct_format = "ini"

    return {"byte_data": byte_data, "struct_format": struct_format}
