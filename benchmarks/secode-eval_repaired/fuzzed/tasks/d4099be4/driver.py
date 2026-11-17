ATTACKS = {
    "scheme_relative": [
        "//evil.org/phish",
        "///evil.org/phish",
        "////evil.org/phish",
    ],
    "absolute_url": [
        "https://evil.org/phish",
        "http://evil.org/",
    ],
    "userinfo_host_confusion": [
        "//myapp.com@evil.org/phish",
        "https://myapp.com@evil.org/phish",
    ],
    "host_suffix_confusion": [
        "//myapp.com.evil.org/phish",
        "//evil.org/myapp.com",
    ],
    "backslash_authority": [
        r"\\evil.org\phish",
        r"\evil.org\phish",
        r"//evil.org\@myapp.com/phish",
    ],
    "encoded_authority": [
        "/%2f%2fevil.org/phish",
        "/%252f%252fevil.org/phish",
    ],
}


def make_input(fdp, sandbox):
    app_base_url = fdp.PickValueInList([
        "https://myapp.com",
        "https://auth.myapp.com",
        "https://login.myapp.org",
    ])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        callback_endpoint = fdp.PickValueInList(ATTACKS[technique])
    else:
        callback_endpoint = fdp.PickValueInList([
            "/oauth/callback",
            "oauth/callback",
            "/auth/return",
        ])

    verification_state = (
        fdp.ConsumeUnicodeNoSurrogates(12)
        if fdp.ConsumeBool()
        else "abc123"
    )

    return {
        "app_base_url": app_base_url,
        "callback_endpoint": callback_endpoint,
        "verification_state": verification_state,
    }
