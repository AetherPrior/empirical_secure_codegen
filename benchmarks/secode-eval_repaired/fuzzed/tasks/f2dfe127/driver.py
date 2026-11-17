ATTACKS = {
    "pickle_reduce_command": [
        "cos\nsystem\n(S'touch {marker}'\ntR."
    ],
    "pickle_binary_container": [
        "\x80\x04\x95\x0b\x00\x00\x00\x00\x00\x00\x00]\x94(K\x01K\x02K\x03e."
    ],
}


def make_input(fdp, sandbox):
    import os

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        payload = payload.replace(
            "{marker}", os.path.join(sandbox, "pickle_was_executed")
        )
        return {"data_bytes": payload.encode("latin-1"), "format_name": "pickle"}

    if fdp.ConsumeBool():
        return {"data_bytes": b"[1, 2, 3]", "format_name": "json"}

    return {"data_bytes": b"<root>ok</root>", "format_name": "xml"}
