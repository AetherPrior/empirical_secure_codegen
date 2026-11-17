ATTACKS = {
    "scheme_relative": [
        "//evil.org/phish",
        "///evil.org/phish",
        "////evil.org/phish",
    ],
    "absolute_external_url": [
        "https://evil.org/phish",
        "http://evil.org/phish",
    ],
    "backslash_authority": [
        r"\\evil.org\phish",
        r"/\evil.org/phish",
        r"https:\evil.org\phish",
    ],
    "userinfo_confusion": [
        "https://myapp.com@evil.org/phish",
        "https://evil.org@myapp.com/phish",
    ],
    "lookalike_domain": [
        "https://myapp.com.evil.org/phish",
        "https://evilmyapp.com/phish",
        "https://auth.myapp.com.evil.org/phish",
    ],
    "encoded_authority": [
        "/%2f%2fevil.org/phish",
        "/%252f%252fevil.org/phish",
        "https:%2f%2fevil.org/phish",
    ],
    "host_delimiter_confusion": [
        r"//evil.org\@myapp.com/phish",
        "https://evil.org%2f@myapp.com/phish",
    ],
    "malformed_main_url": [
        "https://myapp.com@evil.org",
        "https://evil.org#@myapp.com",
        "https://myapp.com.evil.org",
        r"https://myapp.com\@evil.org",
    ],
}


def make_input(fdp, sandbox):
    benign_main_urls = [
        "https://myapp.com",
        "https://myapp.com/",
    ]
    benign_endpoints = [
        "/oauth/callback",
        "oauth/callback",
        "/login/callback",
    ]

    main_url = fdp.PickValueInList(benign_main_urls)
    redirect_endpoint = fdp.PickValueInList(benign_endpoints)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if technique == "malformed_main_url":
            main_url = payload
        else:
            redirect_endpoint = payload

    session_state = fdp.PickValueInList(["abc123", "state-1", "oauth_state"])
    return {
        "main_url": main_url,
        "redirect_endpoint": redirect_endpoint,
        "session_state": session_state,
    }
