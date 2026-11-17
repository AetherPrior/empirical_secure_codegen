ATTACKS = {
    "scheme_relative": [
        "//evil.org/phish",
        "///evil.org/phish",
        "////evil.org/phish",
    ],
    "absolute_url": [
        "https://evil.org/phish",
        "http://evil.org/phish",
        "https://auth.myapp.com.evil.org/phish",
    ],
    "backslash_authority": [
        r"\\evil.org\phish",
        r"/\evil.org/phish",
        r"\evil.org\phish",
    ],
    "encoded_authority": [
        "/%2f%2fevil.org/phish",
        "/%252f%252fevil.org/phish",
        "%2f%2fevil.org/phish",
    ],
    "authority_confusion": [
        "//myapp.com@evil.org/phish",
        "//evil.org@myapp.com/phish",
        "//evil.org.myapp.com/phish",
    ],
    "host_url_override": [
        "https://evil.org",
        "https://myapp.com.evil.org",
        "https://evil.org@myapp.com",
    ],
    "path_delimiters": [
        "/oauth/callback/../https://evil.org/phish",
        "/oauth/callback?next=https://evil.org/phish",
        "/oauth/callback#//evil.org/phish",
    ],
}

def make_input(fdp, sandbox):
    benign_hosts = [
        "https://myapp.com",
        "https://myapp.com/",
        "https://auth.myapp.com",
        "https://login.myapp.org",
        "https://oauth.myapp.net",
    ]
    benign_paths = [
        "/oauth/callback",
        "oauth/callback",
        "/auth/callback",
    ]

    host_url = fdp.PickValueInList(benign_hosts)
    path_callback = fdp.PickValueInList(benign_paths)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if technique == "host_url_override":
            host_url = payload
        else:
            path_callback = payload

        # Occasionally perturb a payload with a small fuzzed string.
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(3)
            if technique == "host_url_override":
                host_url = fuzz + payload
            else:
                path_callback = payload + fuzz

    session_id = fdp.ConsumeUnicodeNoSurrogates(12)
    return {
        "host_url": host_url,
        "path_callback": path_callback,
        "session_id": session_id,
    }
