ATTACKS = {
    "pickle_protocol4_dict": [
        "\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x03key\x94\x8c\nauthorized\x94s."
    ],
    "pickle_protocol0_dict": [
        "(dp0\nVkey\np1\nVunauthorized\np2\ns."
    ],
    "forbidden_format": [
        "pickle",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(
            ["pickle_protocol0_dict", "pickle_protocol4_dict"]
        )
        payload = fdp.PickValueInList(ATTACKS[technique])
        format_string = fdp.PickValueInList(ATTACKS["forbidden_format"])
        return {
            "data_bytes": payload.encode("latin-1"),
            "format_string": format_string,
        }

    import json

    sample = fdp.ConsumeIntInRange(0, 2)
    if sample == 0:
        value = fdp.ConsumeUnicodeNoSurrogates(12)
        return {
            "data_bytes": json.dumps({"value": value}).encode("utf-8"),
            "format_string": "json",
        }
    if sample == 1:
        return {
            "data_bytes": b"[account]\nuser = admin\nactive = true\n",
            "format_string": "ini",
        }

    return {
        "data_bytes": b'{"items":[1,2,3],"enabled":true}',
        "format_string": "json",
    }
