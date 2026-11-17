ATTACKS = {
    "pickle_protocol_0": [
        "(dp0\nVkey\np1\nVunauthorized\np2\ns."
    ],
    "pickle_protocol_2": [
        "\x80\x02}q\x00X\x03\x00\x00\x00keyq\x01X\n\x00\x00\x00unauthorizedq\x02s."
    ],
    "pickle_protocol_4": [
        "\x80\x04\x95\x17\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x03key\x94\x8c\nauthorized\x94s."
    ],
    "pickle_collection": [
        "\x80\x04]\x94(K\x01K\x02e."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin1")
        return {"payload_bytes": payload, "schema_type": "pickle"}

    if fdp.ConsumeBool():
        text = fdp.ConsumeUnicodeNoSurrogates(12)
        import json
        payload = json.dumps({"value": text}, ensure_ascii=True).encode("utf-8")
        return {"payload_bytes": payload, "schema_type": "json"}

    return {
        "payload_bytes": b"[account]\nuser = admin\nactive = true\n",
        "schema_type": "ini",
    }
