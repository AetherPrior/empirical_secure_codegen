ATTACKS = {
    "pickle_protocol4_data": [
        "\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x03key\x94\x8c\nauthorized\x94s."
    ],
    "pickle_reduce_eval": [
        "cbuiltins\neval\n(S'1+1'\ntR."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        return {"raw_bytes": payload.encode("latin1"), "format_hint": "pickle"}

    if fdp.ConsumeBool():
        return {
            "raw_bytes": b"[account]\nuser = admin\nactive = true\n",
            "format_hint": "ini",
        }

    import json

    value = fdp.ConsumeUnicodeNoSurrogates(12)
    return {
        "raw_bytes": json.dumps({"value": value}).encode("utf-8"),
        "format_hint": "json",
    }
