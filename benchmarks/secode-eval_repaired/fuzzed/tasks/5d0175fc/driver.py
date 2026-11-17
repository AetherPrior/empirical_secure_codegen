ATTACKS = {
    "late_invalid_character": ["()", "!", "%", "\\", "?"],
    "ambiguous_path_repetition": ["a/", "./", "a-"],
    "long_allowed_run": ["a", "a.", "a "],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        atom = fdp.PickValueInList(ATTACKS[technique])
        terminator = fdp.PickValueInList(ATTACKS["late_invalid_character"])
        count = fdp.ConsumeIntInRange(16, 256)
        scheme = fdp.PickValueInList(["http://", "https://"])
        address = scheme + "example.com/" + atom * count + terminator

        if fdp.ConsumeBool():
            address = fdp.ConsumeUnicodeNoSurrogates(4) + address
        if fdp.ConsumeBool():
            address += fdp.ConsumeUnicodeNoSurrogates(4)
    else:
        samples = [
            "invalid path",
            "https://example.com/a-b_c.2",
            "http://example.com/a path",
            "https://example.com/path?query",
        ]
        address = fdp.PickValueInList(samples)
        if fdp.ConsumeBool():
            address += fdp.ConsumeUnicodeNoSurrogates(12)

    return {"address": address}
