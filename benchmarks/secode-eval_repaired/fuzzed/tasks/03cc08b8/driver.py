ATTACKS = {
    "absolute_url": [
        "https://evil.org/phish",
        "http://evil.org/",
    ],
    "network_path": [
        "//evil.org/phish",
        "///evil.org/phish",
        "////evil.org/phish",
    ],
    "backslash_authority": [
        r"\\evil.org\phish",
        r"/\\evil.org/phish",
        r"\\\evil.org\phish",
    ],
    "scheme_confusion": [
        "https:evil.org/phish",
        "https:/evil.org/phish",
        "http:///evil.org/phish",
    ],
    "authority_confusion": [
        "//auth.myapp.com@evil.org/phish",
        "//evil.org@auth.myapp.com/phish",
        "//auth.myapp.com.evil.org/phish",
    ],
    "encoded_delimiters": [
        "/%2f%2fevil.org/phish",
        "/%5c%5cevil.org/phish",
        "//evil.org%2f..",
    ],
    "whitespace_controls": [
        " //evil.org/phish",
        "\t//evil.org/phish",
        "//evil.org/\r\nLocation: https://evil.org",
    ],
}


def make_input(fdp, sandbox):
    application_url = fdp.PickValueInList([
        "https://myapp.com",
        "https://auth.myapp.com",
        "https://login.myapp.org",
        "https://oauth.myapp.net",
    ])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        callback_route = fdp.PickValueInList(ATTACKS[technique])
    else:
        callback_route = fdp.PickValueInList([
            "/oauth/callback",
            "oauth/callback",
            "/signin/oauth/callback",
        ])

    token_state = fdp.ConsumeUnicodeNoSurrogates(12)
    if not token_state:
        token_state = "abc123"

    return {
        "application_url": application_url,
        "callback_route": callback_route,
        "token_state": token_state,
    }
