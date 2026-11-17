ATTACKS = {
    "pickle_global_reduce_eval": [
        "cbuiltins\neval\n(S'1+1'\ntR."
    ],
    "pickle_protocol4_object": [
        "\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04flag\x94\x8c\x07exploit\x94s."
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        data = payload.encode("latin1")
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4).encode("utf-8")
            suffix = fdp.ConsumeUnicodeNoSurrogates(4).encode("utf-8")
            data = prefix + data + suffix
        return {
            "data_stream": data,
            "deserialization_method": "pickle",
        }

    if fdp.ConsumeBool():
        return {
            "data_stream": b'{"name":"Alice","age":30}',
            "deserialization_method": "json",
        }

    return {
        "data_stream": b"name,age\nAlice,30\n",
        "deserialization_method": "csv",
    }
