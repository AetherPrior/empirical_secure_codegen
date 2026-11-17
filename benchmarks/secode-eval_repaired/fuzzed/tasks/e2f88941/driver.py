ATTACKS = {
    "pickle_protocol4_mapping": [
        "\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04flag\x94\x8c\x07exploit\x94s."
    ],
    "pickle_legacy_mapping": [
        "}Vflag\nVexploit\ns."
    ],
    "pickle_scalar_protocols": [
        "\x80\x02K*.",
        "\x80\x04K*.",
    ],
    "pickle_reduce_eval": [
        "cbuiltins\neval\n(V1+1\ntR."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin-1")
        if fdp.ConsumeBool():
            payload += fdp.ConsumeBytes(4)
        method = fdp.PickValueInList(["pickle", "pickle", "Pickle", " pickle"])
        return {"data_bytes": payload, "format_method": method}

    samples = [
        (b'{"name":"Alice","age":30}', "json"),
        (b"name,age\nAlice,30\n", "csv"),
        (b'{}', "json"),
        (b"name\n", "csv"),
    ]
    data_bytes, format_method = fdp.PickValueInList(samples)
    if fdp.ConsumeBool():
        data_bytes += fdp.ConsumeBytes(4)
    return {"data_bytes": data_bytes, "format_method": format_method}
