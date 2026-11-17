ATTACKS = {
    "scheme_relative": [
        "//evil.org/phish",
        "///evil.org/phish",
        "//evil.org:443/phish",
        "//myapp.com.evil.org/phish",
    ],
    "absolute_external_url": [
        "https://evil.org/phish",
        "http://evil.org/phish",
        "https:/evil.org/phish",
    ],
    "authority_confusion": [
        "//myapp.com@evil.org/phish",
        "//evil.org@myapp.com/phish",
        "//evil.org#@myapp.com/phish",
        "//evil.org?@myapp.com/phish",
    ],
    "backslash_authority": [
        r"\\evil.org\phish",
        r"/\evil.org/phish",
        r"\/evil.org/phish",
    ],
    "encoded_authority": [
        "/%2f%2fevil.org/phish",
        "/%2F%2Fevil.org/phish",
        "/%5cevil.org/phish",
        "/%252f%252fevil.org/phish",
    ],
    "host_suffix_confusion": [
        "//auth.myapp.com.evil.org/phish",
        "//myapp.com.evil.org/",
        "//evil.org./phish",
    ],
    "base_url_authority_confusion": [
        "https://myapp.com@evil.org",
        "https://evil.org@myapp.com",
        "https://myapp.com.evil.org",
        "https://evil.org",
    ],
}


def make_input(fdp, sandbox):
    benign_bases = [
        "https://myapp.com",
        "https://myapp.com/",
        "https://myapp.com/app",
    ]
    benign_paths = [
        "/oauth/callback",
        "/login/oauth/callback",
        "https://auth.myapp.com/oauth/callback",
        "https://login.myapp.org/oauth/callback",
    ]

    base_url = fdp.PickValueInList(benign_bases)
    callback_path = fdp.PickValueInList(benign_paths)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            callback_path = payload
        else:
            prefix = fdp.ConsumeUnicodeNoSurrogates(2)
            suffix = fdp.ConsumeUnicodeNoSurrogates(2)
            callback_path = prefix + payload + suffix

    if fdp.ConsumeBool():
        payload = fdp.PickValueInList(ATTACKS["base_url_authority_confusion"])
        base_url = payload if fdp.ConsumeBool() else payload + "/app"

    state = fdp.PickValueInList(["abc123", "state-1", "oauth_state"])
    return {
        "base_url": base_url,
        "callback_path": callback_path,
        "state": state,
    }
