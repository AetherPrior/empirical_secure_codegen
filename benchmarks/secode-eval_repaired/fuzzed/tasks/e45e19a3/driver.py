ATTACKS = {
    "pickle_protocol_0": ["(lp0\nI1\naI2\na."],
    "pickle_protocol_4": [
        "\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00]\x94(K\x01K\x02K\x03e."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin1")
        # Pickle ignores trailing bytes, so this can vary the input without
        # preventing a vulnerable implementation from loading the object.
        if fdp.ConsumeBool():
            payload += fdp.ConsumeBytes(4)
        return {"input_data": payload, "data_type": "pickle"}

    benign_samples = [
        (b"[1, 2, 3]", "json"),
        (b'{"ok": true, "value": 1}', "json"),
        (b"<root><item>1</item></root>", "xml"),
    ]
    input_data, data_type = fdp.PickValueInList(benign_samples)
    return {"input_data": input_data, "data_type": data_type}
