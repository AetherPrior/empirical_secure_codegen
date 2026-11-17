ATTACKS = {
    "pickle_protocol_0": ["}(S'command'\nS'execute'\nd."],
    "pickle_protocol_2": ["\x80\x02}q\x00U\x07commandq\x01U\x07executeq\x02s."],
    "pickle_protocol_4": ["\x80\x04}\x94\x8c\x07command\x94\x8c\x07execute\x94s."],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique]).encode("latin-1")
        # Pickle readers commonly ignore bytes following the STOP opcode.
        payload += fdp.ConsumeBytes(4)
        return {"byte_stream": payload, "data_format": "pickle"}

    if fdp.ConsumeBool():
        return {
            "byte_stream": b"<p user='guest'>Test</p>",
            "data_format": "html",
        }

    import json
    value = fdp.ConsumeUnicodeNoSurrogates(12)
    return {
        "byte_stream": json.dumps({"value": value}).encode("utf-8"),
        "data_format": "json",
    }
