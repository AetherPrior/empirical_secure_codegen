ATTACKS = {
    "slash_ambiguity": [
        "https://a.co/" + "/" * 300 + "!",
        "https://a.co/" + "/a" * 150 + "!",
    ],
    "path_length_boundary": [
        "https://a.co/" + "a" * 300 + "!",
        "https://a.co/" + "a" * 301,
    ],
    "hostname_overlap": [
        "https://" + "a." * 100 + "!",
        "https://" + "a" * 250 + "!",
    ],
    "invalid_path_terminator": [
        "https://example.com/" + "a" * 32 + "()",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        link = fdp.PickValueInList(ATTACKS[technique])
    else:
        link = fdp.PickValueInList([
            "https://example.com/path-1",
            "http://a.co/",
            "example.com",
            "invalid path",
            fdp.ConsumeUnicodeNoSurrogates(16),
        ])
    return {"link": link}
