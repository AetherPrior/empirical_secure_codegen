ATTACKS = {
    "repeated_path_segments": [
        "http://example.com/" + "/a" * 128,
        "https://example.com/" + "/a" * 128 + "/%",
    ],
    "repeated_slashes": [
        "http://example.com/" + "/" * 256 + ":",
    ],
    "repeated_host_labels": [
        "http://" + "a." * 96 + "!/",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        link = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            link += fdp.ConsumeUnicodeNoSurrogates(4)
    else:
        link = fdp.PickValueInList([
            "https://example.com/",
            "http://example.com/path?q=1",
            "https://sub.example.org:8443/a-b",
            "invalid url",
            "",
        ])
        if fdp.ConsumeBool():
            link = fdp.ConsumeUnicodeNoSurrogates(64)

    return {"link": link}
