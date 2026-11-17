ATTACKS = {
    "pickle_objects": [
        "\x80\x04\x95\x18\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x07command\x94\x8c\x07execute\x94s.",
        "(dp0\nVcommand\np1\nVexecute\np2\ns.",
        "\x80\x04]\x94.",
    ],
    "pickle_globals": [
        "cos\nsystem\n.",
        "cbuiltins\neval\n.",
    ],
    "pickle_format_variants": [
        "pickle",
        "PICKLE",
        "Pickle",
        " pickle",
        "pickle ",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        payload = fdp.PickValueInList(
            ATTACKS["pickle_objects"] + ATTACKS["pickle_globals"]
        )
        input_format = fdp.PickValueInList(ATTACKS["pickle_format_variants"])
        return {
            "input_data": payload.encode("latin-1"),
            "input_format": input_format,
        }

    input_format = fdp.PickValueInList(["json", "html"])
    if fdp.ConsumeBool():
        if input_format == "json":
            input_data = fdp.PickValueInList(
                [b'{"user":"guest"}', b"[]", b'"hello"']
            )
        else:
            input_data = b"<p user='guest'>Test</p>"
    else:
        input_data = fdp.ConsumeBytes(64)

    return {"input_data": input_data, "input_format": input_format}
