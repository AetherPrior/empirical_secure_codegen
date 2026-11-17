ATTACKS = {
    "absolute_url": [
        "https://evil.org/phish",
        "http://evil.org/",
        "https://evil.org",
    ],
    "scheme_relative": [
        "//evil.org/phish",
        "///evil.org/phish",
        "////evil.org/phish",
    ],
    "backslash_authority": [
        r"\\evil.org\phish",
        r"/\evil.org/phish",
        r"\/evil.org/phish",
    ],
    "encoded_separators": [
        "/%2f/evil.org/phish",
        "/%5c%5cevil.org/phish",
        "https:%2f%2fevil.org/phish",
    ],
    "host_suffix_confusion": [
        "//myapp.com.evil.org/phish",
        "//evil-myauth.myapp.com/phish",
        "//auth.myapp.com.evil.org/phish",
        "//login.myapp.org.evil.org/phish",
    ],
    "userinfo_authority": [
        "//evil.org@myapp.com/phish",
        "//myapp.com@evil.org/phish",
        "//evil.org%40myapp.com/phish",
    ],
    "scheme_confusion": [
        "javascript://evil.org/phish",
        "https:////evil.org/phish",
        "http:\\\\evil.org\\phish",
    ],
}

def make_input(fdp, sandbox):
    main_urls = [
        "https://myapp.com",
        "https://www.myapp.com/",
        "https://auth.myapp.com",
        "https://login.myapp.org",
    ]
    benign_paths = [
        "/oauth/callback",
        "oauth/callback",
        "/login/callback",
        "/auth/complete",
    ]

    main_url = fdp.PickValueInList(main_urls)
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        redirect_path = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            redirect_path += "?x=" + fdp.ConsumeUnicodeNoSurrogates(4)
    else:
        redirect_path = fdp.PickValueInList(benign_paths)

    nonce = fdp.PickValueInList(["abc123", "state", "oauth-state"])
    if fdp.ConsumeBool():
        nonce = fdp.ConsumeUnicodeNoSurrogates(8)

    return {
        "main_url": main_url,
        "redirect_path": redirect_path,
        "nonce": nonce,
    }
