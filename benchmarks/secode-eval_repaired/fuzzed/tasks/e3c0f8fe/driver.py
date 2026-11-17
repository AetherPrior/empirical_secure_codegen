ATTACKS = {
    "pickle_protocol_0": [
        "(dp0\nS'flag'\np1\nS'exploit'\np2\ns.",
    ],
    "pickle_protocol_2": [
        "\x80\x02}q\x00X\x04\x00\x00\x00flagq\x01X\x07\x00\x00\x00exploitq\x02s.",
    ],
    "pickle_protocol_4": [
        "\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04flag\x94\x8c\x07exploit\x94s.",
    ],
}


def make_input(fdp, sandbox):
    import json

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin-1")
        # Pickle ignores trailing bytes, so this preserves the valid payload.
        if fdp.ConsumeBool():
            payload += fdp.ConsumeBytes(8)
        return {
            "serialized_bytes": payload,
            "serialization_method": "pickle",
        }

    method = fdp.PickValueInList(["json", "csv"])
    text = fdp.ConsumeUnicodeNoSurrogates(12)

    if method == "json":
        serialized = json.dumps({"value": text}, ensure_ascii=True).encode("utf-8")
    else:
        safe_text = text.replace(",", " ").replace("\n", " ").replace("\r", " ")
        serialized = ("name,age\n" + safe_text + ",30\n").encode("utf-8")

    return {
        "serialized_bytes": serialized,
        "serialization_method": method,
    }
