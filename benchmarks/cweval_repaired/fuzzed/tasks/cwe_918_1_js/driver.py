ATTACKS = {
    "path_traversal": [
        "../admin",
        "../../internal",
        "a/../../admin",
    ],
    "query_injection": [
        "?url=http://127.0.0.1",
        "?next=http://169.254.169.254/latest/meta-data",
        "x?target=http://localhost",
    ],
    "fragment_injection": [
        "#@127.0.0.1",
        "x#http://localhost",
    ],
    "authority_and_scheme_confusion": [
        "//127.0.0.1",
        "http://127.0.0.1",
        "@127.0.0.1",
        r"\127.0.0.1",
    ],
    "encoded_delimiters": [
        "%2f%2f127.0.0.1",
        "%3furl=http%3a%2f%2flocalhost",
        "%2e%2e%2fadmin",
    ],
}


def make_input(fdp, sandbox):
    def fuzz_text(n):
        return fdp.ConsumeUnicodeNoSurrogates(n).replace("\x00", "")

    api_samples = [
        "https://example.com/api/user",
        "http://service.internal/users",
        "https://api.example.test/v1",
    ]
    api_url = (
        fdp.PickValueInList(api_samples)
        if fdp.ConsumeBool()
        else "https://example.com/" + fuzz_text(8)
    )

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        user_id = fuzz_text(3) + payload + fuzz_text(3)
    else:
        user_id = fdp.PickValueInList(["", "aBc123", "user42", "0"])

    return {"api_url": api_url, "user_id": user_id}
