ATTACKS = {
    "pickle_data": [
        "\x80\x04}\x94.",
        "(dS'command'\nS'execute'\ns.",
        "\x80\x04K\x01.",
        "I1\n.",
    ],
    "pickle_format": ["pickle"],
    "format_alias": ["PICKLE", "Pickle", "pkl", "python-pickle"],
}


def make_input(fdp, sandbox):
    import json

    if fdp.ConsumeBool():
        data = fdp.PickValueInList(ATTACKS["pickle_data"]).encode("latin1")
        stream_format = fdp.PickValueInList(
            ATTACKS["pickle_format"] + ATTACKS["format_alias"]
        )
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4).encode("utf-8")
            suffix = fdp.ConsumeUnicodeNoSurrogates(4).encode("utf-8")
            data = prefix + data + suffix
        return {"serialized_data": data, "stream_format": stream_format}

    if fdp.ConsumeBool():
        value = fdp.ConsumeUnicodeNoSurrogates(12)
        serialized_data = json.dumps(value).encode("utf-8")
        stream_format = "json"
    else:
        text = fdp.ConsumeUnicodeNoSurrogates(12)
        serialized_data = ("<p user='guest'>" + text + "</p>").encode("utf-8")
        stream_format = "html"

    return {"serialized_data": serialized_data, "stream_format": stream_format}
