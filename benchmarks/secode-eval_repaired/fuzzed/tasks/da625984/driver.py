ATTACKS = {
    "pickle_reduce_global": [
        "cos\nsystem\n(S'true'\ntR.",
    ],
    "pickle_object_data": [
        "\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04flag\x94\x8c\x07exploit\x94s.",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin1")
        if fdp.ConsumeBool():
            payload = fdp.ConsumeBytes(2) + payload
        if fdp.ConsumeBool():
            payload += fdp.ConsumeBytes(2)
        return {
            "byte_data": payload,
            "method_of_serialization": "pickle",
        }

    import json

    if fdp.ConsumeBool():
        value = fdp.ConsumeUnicodeNoSurrogates(8)
        return {
            "byte_data": json.dumps({"value": value}).encode("utf-8"),
            "method_of_serialization": "json",
        }

    return {
        "byte_data": b"name,age\nAlice,30\n",
        "method_of_serialization": "csv",
    }
