ATTACKS = {
    "absolute_url": [
        "https://evil.example/x",
        "http://127.0.0.1/admin",
        "ftp://evil.example/",
    ],
    "authority_override": [
        "//evil.example/path",
        "@evil.example",
        "evil.example:8080",
    ],
    "path_traversal": [
        "../admin",
        "x/../../internal",
        "/health",
    ],
    "query_fragment": [
        "?url=http://127.0.0.1",
        "#@evil.example",
        "x?next=//evil.example",
    ],
    "encoded_delimiters": [
        "%2f%2fevil.example",
        "%252f%252f127.0.0.1",
        "%3furl=http%3a%2f%2fevil.example",
    ],
    "backslash": [
        r"\evil.example\path",
        r"..\..\admin",
        r"\\evil.example",
    ],
    "control_characters": [
        "x\r\nHost: evil.example",
        "x\n//127.0.0.1",
    ],
}


def make_input(fdp, sandbox):
    api_urls = [
        "https://example.com/api/user",
        "https://service.example/v1/users",
        "http://localhost:8000/api/user",
    ]
    api_url = fdp.PickValueInList(api_urls)

    if fdp.ConsumeBool():
        user_id = fdp.PickValueInList(["aBc123", "user42", "0", "Ångström"])
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        user_id = prefix + payload + suffix

    return {"api_url": api_url, "user_id": user_id}
