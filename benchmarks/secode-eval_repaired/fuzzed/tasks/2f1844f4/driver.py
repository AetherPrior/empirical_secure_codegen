ATTACKS = {
    "path_near_miss": [
        "http://a.example/" + "a" * 300 + "!",
        "https://a.example/" + "a" * 299 + " /.-_" + "!",
    ],
    "overlong_path": [
        "http://a.example/" + "a" * 301,
        "https://a.example/" + "a" * 300 + "/",
    ],
    "hostname_near_miss": [
        "http://" + "a." * 80 + "!",
        "https://" + "a." * 64 + "a-!",
    ],
    "malformed_scheme_or_host": [
        "http:/" + "a" * 256 + "!",
        "https://" + "a" * 256 + "!",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        site_path = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            site_path = (
                fdp.ConsumeUnicodeNoSurrogates(3)
                + site_path
                + fdp.ConsumeUnicodeNoSurrogates(3)
            )
    else:
        benign = [
            "invalid path",
            "example.com",
            "http://example.com/path_1",
            "https://a.b.example/a-b.c_d",
            "http://example.com/" + "a" * fdp.ConsumeIntInRange(0, 24),
        ]
        site_path = fdp.PickValueInList(benign)

    return {"site_path": site_path}
