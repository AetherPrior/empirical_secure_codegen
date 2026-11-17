ATTACKS = {
    "pickle_protocol4": [
        "\x80\x04\x95\x18\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x07command\x94\x8c\x07execute\x94s.",
        "\x80\x04}\x94.",
    ],
    "pickle_protocol0": [
        "(dp0\nVcommand\np1\nVexecute\np2\ns.",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        return {
            "content": payload.encode("latin1"),
            "format_type": "pickle",
        }

    format_type = fdp.PickValueInList(["json", "html"])
    if format_type == "json":
        samples = [
            b'{"user":"guest","active":true}',
            b'[]',
            b'{"items":[1,2,3]}',
        ]
    else:
        samples = [
            b"<p user='guest'>Test</p>",
            b"<div id='main'>Hello</div>",
            b"<img src='x' alt='y'>",
        ]

    if fdp.ConsumeBool():
        content = fdp.PickValueInList(samples)
    else:
        text = fdp.ConsumeUnicodeNoSurrogates(12)
        if format_type == "json":
            content = ('{"value":' + __import__("json").dumps(text) + "}").encode("utf-8")
        else:
            content = ("<p data-value='" + text.replace("'", "") + "'>text</p>").encode("utf-8")

    return {"content": content, "format_type": format_type}
