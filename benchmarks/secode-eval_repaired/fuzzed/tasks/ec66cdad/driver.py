ATTACKS = {
    "pickle_stream": [
        "\x80\x04\x95\x18\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x07command\x94\x8c\x07execute\x94s.",
        "(dp0\nVcommand\np1\nVexecute\np2\ns.",
    ],
    "unsafe_format_selector": ["pickle"],
}


def make_input(fdp, sandbox):
    import json

    if fdp.ConsumeBool():
        payload = fdp.PickValueInList(ATTACKS["pickle_stream"])
        serialization_type = fdp.PickValueInList(
            ATTACKS["unsafe_format_selector"]
        )
        return {
            "byte_data": payload.encode("latin-1"),
            "serialization_type": serialization_type,
        }

    text = fdp.ConsumeUnicodeNoSurrogates(12)
    if fdp.ConsumeBool():
        byte_data = json.dumps({"value": text}).encode("utf-8")
        serialization_type = "json"
    else:
        byte_data = f"<p user='guest'>{text}</p>".encode("utf-8")
        serialization_type = "html"

    return {"byte_data": byte_data, "serialization_type": serialization_type}
