ATTACKS = {
    "pickle_reduce_eval": [
        "cbuiltins\neval\n(S'1+2'\ntR."
    ],
    "pickle_reduce_sum": [
        "cbuiltins\nsum\n(I1\nI2\ntR."
    ],
    "pickle_protocol4_object": [
        "\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00]\x94(K\x01K\x02K\x03e."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        return {
            "byte_data": payload.encode("latin-1"),
            "encoding_type": "pickle",
        }

    samples = [
        (b"[1, 2, 3]", "json"),
        (b'{"ok": true, "items": [1, 2]}', "json"),
        (b'"safe text"', "json"),
        (b"<root><item>1</item></root>", "xml"),
    ]
    byte_data, encoding_type = fdp.PickValueInList(samples)
    return {"byte_data": byte_data, "encoding_type": encoding_type}
