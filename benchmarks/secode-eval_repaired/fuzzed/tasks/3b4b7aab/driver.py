ATTACKS = {
    "scheme_relative": [
        "//evil.org/phish",
        "///evil.org/phish",
        "//evil.org:443/phish",
    ],
    "absolute_url": [
        "https://evil.org/phish",
        "http://evil.org/",
        "https://auth.myapp.com.evil.org/callback",
        "https://myapp.com.evil.org/callback",
    ],
    "userinfo_confusion": [
        "//myapp.com@evil.org/phish",
        "https://auth.myapp.com@evil.org/phish",
        "//evil.org@myapp.com/phish",
    ],
    "domain_suffix_and_trailing_dot": [
        "//evil.org.myapp.com/phish",
        "//myapp.com.evil.org/phish",
        "//evil.org./phish",
    ],
    "backslash_confusion": [
        r"\\evil.org\phish",
        r"\evil.org\phish",
        r"https://evil.org\@myapp.com/phish",
    ],
    "encoded_authority": [
        "/%2f%2fevil.org/phish",
        "//evil.org%2f@myapp.com/phish",
        "https://evil.org%2f.myapp.com/phish",
    ],
    "fragment_and_query_confusion": [
        "//evil.org/phish#@myapp.com",
        "//evil.org/phish?next=https://myapp.com",
    ],
    "untrusted_root": [
        "https://evil.org",
        "https://myapp.com.evil.org",
        "https://myapp.com@evil.org",
        "//evil.org",
    ],
}


def make_input(fdp, sandbox):
    benign_roots = ["https://myapp.com", "https://myapp.com/"]
    benign_callbacks = ["/oauth/callback", "oauth/callback", "/login/callback"]

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])

        if family == "untrusted_root" or fdp.ConsumeBool():
            root_url = payload
            callback_uri = fdp.PickValueInList(benign_callbacks)
        else:
            root_url = fdp.PickValueInList(benign_roots)
            callback_uri = payload
    else:
        root_url = fdp.PickValueInList(benign_roots)
        callback_uri = fdp.PickValueInList(benign_callbacks)

    state = fdp.ConsumeUnicodeNoSurrogates(12)
    return {
        "root_url": root_url,
        "callback_uri": callback_uri,
        "session_state": state,
    }
