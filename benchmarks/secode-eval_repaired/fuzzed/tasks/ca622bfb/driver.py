ATTACKS = {
    "scheme_relative": [
        "//evil.org/phish",
        "///evil.org/phish",
        "////evil.org/phish",
    ],
    "absolute_url": [
        "https://evil.org/phish",
        "http://evil.org/phish",
        "https:evil.org/phish",
    ],
    "backslash_authority": [
        r"\\evil.org\phish",
        r"/\evil.org/phish",
        r"\evil.org\phish",
    ],
    "host_confusion": [
        "//myapp.com.evil.org/phish",
        "//evil.org@myapp.com/phish",
        "//evil.org./phish",
        "//evil.org:443/phish",
    ],
    "encoded_authority": [
        "%2f%2fevil.org/phish",
        "//%65vil.org/phish",
        "//evil.org%5c@myapp.com/phish",
    ],
    "alternate_schemes": [
        "javascript:alert(1)",
        "data:text/html,evil",
    ],
    "state_query_injection": [
        "x&next=https://evil.org",
        "x%26next%3Dhttps%3A%2F%2Fevil.org",
    ],
    "root_domain_confusion": [
        "https://myapp.com.evil.org",
        "https://evil.org@myapp.com",
        "https://evil.org",
    ],
}


def make_input(fdp, sandbox):
    benign_roots = [
        "https://myapp.com",
        "https://auth.myapp.com",
        "https://login.myapp.org",
        "https://oauth.myapp.net",
    ]
    benign_paths = [
        "/oauth/callback",
        "/auth/callback",
        "oauth/callback",
    ]

    root_url = fdp.PickValueInList(benign_roots)
    path_for_callback = fdp.PickValueInList(benign_paths)
    session_token = fdp.ConsumeUnicodeNoSurrogates(12)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "root_domain_confusion":
            root_url = payload
        elif technique == "state_query_injection":
            session_token = payload
        else:
            path_for_callback = payload

    return {
        "root_url": root_url,
        "path_for_callback": path_for_callback,
        "session_token": session_token,
    }
