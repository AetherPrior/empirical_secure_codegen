ATTACKS = {
    "overlapping_host_suffix": [
        "http://" + "a" * 128 + ".com!",
        "https://" + "a" * 256 + ".com!",
        "http://" + ("a." * 96) + "com!",
    ],
    "repeated_host_labels": [
        "http://" + ("a." * 120) + "a!",
        "https://" + ("a-." * 80) + "com!",
    ],
    "path_length_boundary": [
        "http://example.com/" + "a" * 301 + "!",
        "https://example.com/" + ("a/" * 150) + "a!",
    ],
    "malformed_suffix": [
        "http://" + "a" * 192 + ".c1!",
        "https://" + ("a." * 64) + "c!",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        link = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            # Add a small fuzzed tail while keeping the long near-match intact.
            link += fdp.ConsumeUnicodeNoSurrogates(2)
    else:
        link = fdp.PickValueInList([
            "invalid path",
            "https://example.com/",
            "http://a-b.example/path_1",
            "example.org/a-b",
            fdp.ConsumeUnicodeNoSurrogates(32),
        ])
    return {"link": link}
