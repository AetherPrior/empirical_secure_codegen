ATTACKS = {
    "pickle_protocol_0": [
        "}.",
        "].",
        "I42\n.",
    ],
    "pickle_protocol_2": [
        "\x80\x02}q\x00.",
        "\x80\x02K*.",
    ],
    "pickle_protocol_4": [
        "\x80\x04}\x94.",
        "\x80\x04K*.",
        "\x80\x04\x95\x18\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x07command\x94\x8c\x07execute\x94s.",
    ],
    "format_confusion": [
        "pickle",
        "Pickle",
        "PICKLE",
        " pickle",
        "pickle ",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "format_confusion":
            serialization_format = payload
            pickle_technique = fdp.PickValueInList(
                ["pickle_protocol_0", "pickle_protocol_2", "pickle_protocol_4"]
            )
            payload = fdp.PickValueInList(ATTACKS[pickle_technique])
        else:
            serialization_format = "pickle"

        stream = payload.encode("latin-1")
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeBytes(4)
            suffix = fdp.ConsumeBytes(4)
            stream = prefix + stream + suffix
    else:
        benign_samples = [
            (b'{"user":"guest","items":[1,true]}', "json"),
            (b"<p user='guest'>Test</p>", "html"),
        ]
        stream, serialization_format = fdp.PickValueInList(benign_samples)

    return {
        "stream": stream,
        "serialization_format": serialization_format,
    }
