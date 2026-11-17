ATTACKS = {
    "repeated_path_atom": ["a", "aa"],
    "ambiguous_segments": ["a/", "a/a"],
    "repeated_dots": ["a.", ".."],
    "invalid_trailing_character": ["!", " ", "#"],
    "oversized_suffix": ["a"],
}


def make_input(fdp, sandbox):
    benign = [
        "invalid path",
        "https://example.com",
        "http://example.com/a/b",
        "example.com/path",
        "https://sub.example.org/" + fdp.ConsumeUnicodeNoSurrogates(8).replace("/", "x"),
    ]

    if not fdp.ConsumeBool():
        return {"path": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "oversized_suffix":
        count = fdp.ConsumeIntInRange(295, 315)
        suffix = "/" + payload * count
    elif technique == "invalid_trailing_character":
        atom = fdp.PickValueInList(ATTACKS["repeated_path_atom"])
        count = fdp.ConsumeIntInRange(130, 155)
        suffix = "/" + atom * count + payload
    else:
        count = fdp.ConsumeIntInRange(130, 155)
        suffix = "/" + payload * count
        if fdp.ConsumeBool():
            suffix += fdp.PickValueInList(ATTACKS["invalid_trailing_character"])

    scheme = fdp.PickValueInList(["", "http://", "https://"])
    host = fdp.PickValueInList(["example.com", "sub.example.org", "a.b.example.net"])
    return {"path": scheme + host + suffix}
