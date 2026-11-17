ATTACKS = {
    "repeated_host_near_miss": [
        "https://" + "a" * 256 + ".com(",
        "http://" + "a" * 512 + ".com!",
    ],
    "ambiguous_host_separators": [
        "https://" + "a." * 160 + "!",
        "http://" + ("a-" * 160) + ".com!",
    ],
    "path_length_near_miss": [
        "https://example.com/" + "a" * 301 + "(",
        "http://example.com/" + "a" * 300 + "!",
    ],
    "suffix_length_near_miss": [
        "https://example." + "a" * 7,
        "http://example." + "a" * 6 + "!",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "invalid path",
        "https://example.com",
        "http://example.com/a/b-c_1",
        "https://a.b/path/",
    ]

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        value = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            value = fdp.ConsumeUnicodeNoSurrogates(3) + value
        if fdp.ConsumeBool():
            value += fdp.ConsumeUnicodeNoSurrogates(3)
    else:
        value = fdp.PickValueInList(benign)
        if fdp.ConsumeBool():
            value += fdp.ConsumeUnicodeNoSurrogates(8)

    return {"path_string": value}
