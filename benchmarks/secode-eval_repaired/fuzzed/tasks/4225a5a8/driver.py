ATTACKS = {
    "pickle_protocol0": ["(lp0\nI1\naI2\naI3\na."],
    "pickle_protocol2": ["\x80\x02]q\x00(K\x01K\x02K\x03e."],
    "pickle_protocol4": [
        "\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00]\x94(K\x01K\x02K\x03e."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        return {"raw_data": payload.encode("latin-1"), "method_name": "pickle"}

    import html
    import json

    text = fdp.ConsumeUnicodeNoSurrogates(16)
    if fdp.ConsumeBool():
        raw_data = json.dumps(
            {"value": text}, ensure_ascii=True, separators=(",", ":")
        ).encode("utf-8")
        method_name = "json"
    else:
        escaped = html.escape(text, quote=True)
        raw_data = f"<root>{escaped}</root>".encode("utf-8")
        method_name = "xml"

    return {"raw_data": raw_data, "method_name": method_name}
