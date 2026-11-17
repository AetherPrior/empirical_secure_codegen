ATTACKS = {
    "pickle_protocol_0": [
        "(lp0\nI1\naI2\na.",
        "cbuiltins\neval\n(S'1+1'\ntR.",
    ],
    "pickle_protocol_2": [
        "\x80\x02]q\x00(K\x01K\x02e.",
    ],
    "pickle_protocol_4": [
        "\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00]\x94(K\x01K\x02K\x03e.",
        "\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x01a\x94K\x01s.",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        return {"encoded_data": payload.encode("latin-1"), "method": "pickle"}

    benign_samples = [
        (b"[1, 2, 3]", "json"),
        (b'{"a": 1}', "json"),
        (b'"hello"', "json"),
        (b"<root>ok</root>", "xml"),
    ]
    encoded_data, method = fdp.PickValueInList(benign_samples)
    return {"encoded_data": encoded_data, "method": method}
