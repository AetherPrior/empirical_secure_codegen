ATTACKS = {
    "long_url_component": [
        "https://example.com/" + "a" * 255,
        "https://example.com/" + "a" * 300 + "!",
    ],
    "repeated_path_segments": [
        "https://example.com/" + "a/" * 128 + "!",
        "/" + "a/" * 150 + "!",
    ],
    "ambiguous_path_characters": [
        "https://example.com/" + "a" * 150 + "/" + "a" * 150 + "!",
        "/" + "a" * 200 + "." + "a" * 100 + "!",
    ],
    "repeated_host_labels": [
        "https://" + "a." * 100 + "example.com/" + "x" * 100 + "!",
        "http://" + "a-" * 100 + "example.com/" + "x" * 100 + "!",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        value = fdp.PickValueInList(ATTACKS[family])

        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
            if fdp.ConsumeBool():
                value = fuzz + value
            else:
                value = value + fuzz
        return {"string": value}

    benign_values = [
        "/",
        "/users/123",
        "https://example.com/path",
        "http://example.com/",
        "invalid path",
        "",
    ]
    return {"string": fdp.PickValueInList(benign_values)}
