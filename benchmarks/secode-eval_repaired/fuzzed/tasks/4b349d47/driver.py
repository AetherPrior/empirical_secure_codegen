ATTACKS = {
    "pickle_protocol_list": [
        "\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00]\x94(K\x01K\x02K\x03e."
    ],
    "pickle_global_call": [
        "cos\nsystem\n(S'true'\ntR."
    ],
    "pickle_malformed": [
        "\x80\x04not-a-valid-pickle"
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        serialized_data = fdp.PickValueInList(ATTACKS[technique]).encode("latin1")
        format_type = "pickle"
    else:
        serialized_data = fdp.PickValueInList([
            b"[1, 2, 3]",
            b'{"name":"sample","value":7}',
            b"<root><item>sample</item></root>",
            b"null",
        ])
        format_type = fdp.PickValueInList(["json", "xml"])

    if fdp.ConsumeBool():
        serialized_data += fdp.ConsumeBytes(4)

    return {"serialized_data": serialized_data, "format_type": format_type}
