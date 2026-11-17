ATTACKS = {
    "pickle_protocol4": [
        "\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00]\x94(K\x01K\x02K\x03e."
    ],
    "pickle_protocol0": [
        "(lp0\nI1\naI2\na."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        return {
            "raw_data": payload.encode("latin-1"),
            "serialization_format": "pickle",
        }

    import json
    from xml.sax.saxutils import escape

    text = fdp.ConsumeUnicodeNoSurrogates(16)
    if fdp.ConsumeBool():
        raw_data = json.dumps([text, 1, True]).encode("utf-8")
        serialization_format = "json"
    else:
        raw_data = f"<root>{escape(text)}</root>".encode("utf-8")
        serialization_format = "xml"

    return {
        "raw_data": raw_data,
        "serialization_format": serialization_format,
    }
