ATTACKS = {
    "pickle_plain_object": [
        "\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04flag\x94\x8c\x07exploit\x94s."
    ],
    "pickle_reduce_builtin": [
        "cbuiltins\nlen\n(I1\ntR."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin1")
        if fdp.ConsumeBool():
            payload += fdp.ConsumeBytes(4)
        return {"stream_bytes": payload, "method_type": "pickle"}

    method = fdp.PickValueInList(["csv", "json"])
    if method == "csv":
        stream = b"name,age\nAlice,30\n"
    else:
        stream = b'{"name":"Alice","age":30}'
    return {"stream_bytes": stream, "method_type": method}
