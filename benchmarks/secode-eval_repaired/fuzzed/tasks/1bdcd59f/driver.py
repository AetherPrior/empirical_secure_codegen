ATTACKS = {
    "ambiguous_dotted_host": [
        "http://" + "a." * 32 + "com!",
        "http://" + "a." * 64 + "com!",
        "http://" + "a." * 128 + "com!",
    ],
    "long_host_near_miss": [
        "http://" + "a" * 128 + ".com!",
        "http://" + "a" * 256 + ".com!",
    ],
    "path_limit_near_miss": [
        "http://a.com/" + "a" * 300 + "!",
        "http://a.com/" + "a/" * 128 + "!",
        "http://a.com/" + "a " * 128 + "!",
    ],
    "invalid_path_suffix": [
        "https://example.com/" + "a" * 32 + "()",
        "http://example.com/" + "a/" * 32 + "()",
    ],
}

_BENIGN = [
    "example.com",
    "http://example.com/",
    "https://sub.example.co.uk/path/to-page_1",
    "http://a.co/a b.c-d",
    "invalid path",
    "",
]


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        u = fdp.PickValueInList(ATTACKS[family])
    else:
        u = fdp.PickValueInList(_BENIGN)
    return {"u": u}
