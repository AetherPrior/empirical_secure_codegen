ATTACKS = {
    "scheme_relative": [
        "//evil.org/phish",
        "///evil.org/phish",
        "//evil.org",
    ],
    "absolute_url": [
        "https://evil.org/phish",
        "http://evil.org/",
        "https://evil.org",
    ],
    "backslash_authority": [
        r"\\evil.org\phish",
        r"/\evil.org/phish",
        r"\\evil.org/phish",
    ],
    "trusted_domain_confusion": [
        "//myapp.com.evil.org/",
        "//evilmyapp.com/",
        "//auth.myapp.com@evil.org/",
        "//myapp.com@evil.org/",
    ],
    "encoded_authority": [
        "/%2f%2fevil.org/phish",
        "/%5c%5cevil.org/phish",
        "//%65vil.org/phish",
    ],
    "malicious_base_domain": [
        "https://evil.org",
        "https://myapp.com.evil.org",
        "https://evilmyapp.com",
    ],
}


def make_input(fdp, sandbox):
    safe_bases = [
        "https://myapp.com",
        "https://auth.myapp.com",
        "https://login.myapp.org",
        "https://oauth.myapp.net",
    ]
    safe_paths = [
        "/oauth/callback",
        "/auth/callback",
        "/login/complete",
    ]
    states = ["abc123", "state-42", "oauth_state"]

    main_url = fdp.PickValueInList(safe_bases)
    redirect_path = fdp.PickValueInList(safe_paths)
    token_state = fdp.PickValueInList(states)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if technique == "malicious_base_domain":
            main_url = payload
        else:
            redirect_path = payload

    return {
        "main_url": main_url,
        "redirect_path": redirect_path,
        "token_state": token_state,
    }
