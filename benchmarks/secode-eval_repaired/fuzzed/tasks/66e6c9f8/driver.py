ATTACKS = {
    "pickle_payloads": [
        "\x80\x04N.",
        "\x80\x04}\x94.",
        "\x80\x02}q\x00.",
        "\x80\x04\x95\x18\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x07command\x94\x8c\x07execute\x94s.",
    ],
    "pickle_format_variants": [
        "pickle",
        "Pickle",
        "PICKLE",
        "pickle ",
        "application/x-python-pickle",
    ],
}


def make_input(fdp, sandbox):
    import html
    import json

    if fdp.ConsumeBool():
        stream = fdp.PickValueInList(ATTACKS["pickle_payloads"]).encode("latin-1")
        stream_format = fdp.PickValueInList(ATTACKS["pickle_format_variants"])
    else:
        text = fdp.ConsumeUnicodeNoSurrogates(12)
        if fdp.ConsumeBool():
            stream_format = "json"
            stream = json.dumps({"value": text}).encode("utf-8")
        else:
            stream_format = "html"
            stream = ("<p user='guest'>" + html.escape(text) + "</p>").encode("utf-8")

    return {"stream": stream, "stream_format": stream_format}
