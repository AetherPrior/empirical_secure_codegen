ATTACKS = {
    "pickle_protocol0": [
        "(dS'key'\nS'value'\ns.",
        "(lI1\naI2\na.",
    ],
    "pickle_protocol4": [
        "\x80\x04\x95\x12\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x03key\x94\x8c\x05value\x94s.",
    ],
    "yaml_python_object_apply": [
        "!!python/object/apply:builtins.complex [1, 2]",
        "!!python/object/apply:builtins.set [[a, b]]",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique.startswith("pickle"):
            data = payload.encode("latin-1")
            signature = "pickle"
        else:
            data = payload
            signature = "yaml"

        if fdp.ConsumeBool() and signature == "yaml":
            fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
            data = "# " + fuzz + "\n" + data

        return {"data": data, "signature": signature}

    benign_samples = [
        ("[1, 2, 3]", "json"),
        ('{"key": "value"}', "json"),
        ("name: sample\ncount: 2", "yaml"),
    ]
    data, signature = fdp.PickValueInList(benign_samples)
    if fdp.ConsumeBool():
        data = data.encode("utf-8")
    return {"data": data, "signature": signature}
