ATTACKS = {
    "pickle_protocol4": [
        "\x80\x04\x95\x18\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x07command\x94\x8c\x07execute\x94s.",
        "\x80\x04}\x94.",
        "\x80\x04]\x94.",
    ],
    "pickle_protocol0": [
        "(d.",
        "cbuiltins\nlist\n)R.",
    ],
    "pickle_format_alias": [
        "PICKLE",
        "Pickle",
        "pickle ",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(
            ["pickle_protocol4", "pickle_protocol0"]
        )
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin1")
        data_format = "pickle"

        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(4).encode("utf-8")
            payload += suffix
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(3).encode("utf-8")
            payload = prefix + payload

        if fdp.ConsumeBool():
            data_format = fdp.PickValueInList(ATTACKS["pickle_format_alias"])
        return {"data": payload, "data_format": data_format}

    benign_samples = [
        (b'{"ok":true,"n":1}', "json"),
        (b'{"items":["a",2]}', "json"),
        (b"<p user='guest'>Test</p>", "html"),
        (b"<div>hello</div>", "html"),
    ]
    data, data_format = fdp.PickValueInList(benign_samples)
    return {"data": data, "data_format": data_format}
