ATTACKS = {
    "long_repetition_near_miss": [
        "https://example.com/" + "a" * 192 + "\x00",
        "https://example.com/" + "a" * 192 + "!",
    ],
    "ambiguous_path_segments": [
        "https://example.com/" + "a/" * 96 + "\x00",
        "http://example.com/" + "a/" * 96 + "!",
    ],
    "repeated_domain_labels": [
        "https://" + "a." * 96 + "a!",
        "http://" + "a." * 96 + "a\x00",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        input_path = fdp.PickValueInList(ATTACKS[family])
    else:
        benign = [
            "invalid path",
            "https://example.com/",
            "http://example.org/a/b?x=1",
            "/relative/path",
        ]
        input_path = fdp.PickValueInList(benign)
        if fdp.ConsumeBool():
            input_path += fdp.ConsumeUnicodeNoSurrogates(8)

    return {"input_path": input_path}
