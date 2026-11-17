ATTACKS = {
    "path_injection": [
        "/admin",
        "../internal",
        "x/../../admin",
        "\\\\internal",
    ],
    "authority_injection": [
        "//127.0.0.1",
        "https://127.0.0.1",
        "@127.0.0.1",
        "x@127.0.0.1",
    ],
    "query_and_fragment_injection": [
        "?url=http://127.0.0.1",
        "&next=http://127.0.0.1",
        "#@127.0.0.1",
    ],
    "percent_encoded_delimiters": [
        "%2f%2f127.0.0.1",
        "%40127.0.0.1",
        "%3furl=http://127.0.0.1",
    ],
    "whitespace_delimiters": [
        "x y",
        "x\ty",
        "x\ny",
    ],
}


def make_input(fdp, sandbox):
    api_urls = [
        "https://example.com/api/user",
        "https://api.example.test/v1/users",
        "http://localhost:8000/users",
    ]
    api_url = fdp.PickValueInList(api_urls)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        user_id = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "")
            suffix = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "")
            user_id = prefix + user_id + suffix
    else:
        benign_ids = ["aBc123", "user42", "007", "Alice"]
        if fdp.ConsumeBool():
            user_id = fdp.PickValueInList(benign_ids)
        else:
            fuzz_text = fdp.ConsumeUnicodeNoSurrogates(8).replace("\x00", "")
            user_id = "".join(c for c in fuzz_text if c.isascii() and c.isalnum())
            if not user_id:
                user_id = fdp.PickValueInList(benign_ids)

    return {"api_url": api_url, "user_id": user_id}
