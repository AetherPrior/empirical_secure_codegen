ATTACKS = {
    "protocol_relative": [
        "//evil.org/phish",
        "///evil.org/phish",
        "////evil.org/phish",
    ],
    "absolute_url": [
        "https://evil.org/phish",
        "http://evil.org/",
        "https://evil.org",
    ],
    "backslash_authority": [
        r"\\evil.org\phish",
        r"/\evil.org/phish",
        r"\\evil.org",
    ],
    "deceptive_host": [
        "//myapp.com.evil.org/phish",
        "//auth.myapp.com.evil.org/phish",
        "//evil.org/myapp.com",
    ],
    "userinfo_authority": [
        "https://myapp.com@evil.org/phish",
        "https://evil.org@myapp.com/phish",
        "//user@evil.org/phish",
    ],
    "encoded_authority": [
        "%2f%2fevil.org/phish",
        "%252f%252fevil.org/phish",
        "/%2f%2fevil.org/phish",
    ],
    "query_fragment": [
        "?next=https://evil.org/phish",
        "#//evil.org/phish",
        "/oauth#https://evil.org/phish",
    ],
    "state_parameter_injection": [
        "x&redirect_uri=https://evil.org/phish",
        "x%26redirect_uri%3Dhttps%3A%2F%2Fevil.org",
        "x#https://evil.org/phish",
    ],
    "untrusted_base": [
        "https://evil.org",
        "https://myapp.com.evil.org",
        "https://user@evil.org",
    ],
}


def make_input(fdp, sandbox):
    benign_bases = [
        "https://myapp.com",
        "https://auth.myapp.com",
        "https://login.myapp.org",
    ]
    benign_paths = [
        "/oauth/token",
        "/auth/callback",
        "/oauth/callback",
    ]
    benign_states = ["abc123", "state-42", "oauth_state"]

    app_base_url = fdp.PickValueInList(benign_bases)
    token_path = fdp.PickValueInList(benign_paths)
    session_state = fdp.PickValueInList(benign_states)

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])

        if family == "untrusted_base":
            app_base_url = payload
        elif family == "state_parameter_injection":
            session_state = payload
        else:
            token_path = payload

        # Sometimes put short fuzz text next to the chosen payload to exercise
        # parsing and normalization boundaries without losing the payload.
        if fdp.ConsumeBool():
            extra = fdp.ConsumeUnicodeNoSurrogates(6)
            if extra:
                if family == "untrusted_base":
                    app_base_url = app_base_url + extra
                elif family == "state_parameter_injection":
                    session_state = extra + session_state
                else:
                    token_path = token_path + extra

    return {
        "app_base_url": app_base_url,
        "token_path": token_path,
        "session_state": session_state,
    }
