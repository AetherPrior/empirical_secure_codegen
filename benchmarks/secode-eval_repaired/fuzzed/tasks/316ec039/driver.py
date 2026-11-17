ATTACKS = {
    "pickle_reduce_os_system": [
        "cos\nsystem\n(S'touch __SANDBOX__/pickle_marker'\ntR.",
        "cos\nsystem\n(S'echo fuzz > __SANDBOX__/pickle_marker2'\ntR.",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        serialized_data = payload.replace("__SANDBOX__", sandbox).encode("utf-8")
        if fdp.ConsumeBool():
            serialized_data += fdp.ConsumeBytes(4)
        method = "pickle"
    else:
        method = fdp.PickValueInList(["json", "csv"])
        samples = {
            "json": [b'{"name":"Alice","age":30}', b"[]", b"null"],
            "csv": [b"name,age\nAlice,30\n", b"a,b\n1,2\n", b""],
        }
        serialized_data = fdp.PickValueInList(samples[method])

    return {
        "serialized_data": serialized_data,
        "deserialization_method": method,
    }
