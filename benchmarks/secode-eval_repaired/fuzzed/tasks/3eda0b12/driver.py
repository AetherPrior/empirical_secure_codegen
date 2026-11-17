ATTACKS = {
    "absolute_external": [
        "https://evil.com/hack",
        "http://evil.com/",
        "https://evil.com:443/path",
    ],
    "scheme_relative": [
        "//evil.com/hack",
        "///evil.com/hack",
        "////evil.com/hack",
    ],
    "host_confusion": [
        "https://myapp.com.evil.com/",
        "https://trusted-site.com.evil.com/",
        "//evil.com/myapp.com",
    ],
    "userinfo_confusion": [
        "https://evil.com@myapp.com/",
        "https://trusted-site.com@evil.com/",
    ],
    "backslash_authority": [
        r"\\evil.com\hack",
        r"/\evil.com/hack",
    ],
    "encoded_authority": [
        "%2f%2fevil.com/hack",
        "/%2f%2fevil.com/hack",
        "/%5c%5cevil.com/hack",
    ],
    "scheme_parser_confusion": [
        "https:evil.com",
        "https:/evil.com",
        "HtTpS://evil.com/",
    ],
}

def make_input(fdp, sandbox):
    main_urls = [
        "https://myapp.com",
        "https://myapp.com/",
        "http://myapp.com",
    ]
    benign_targets = [
        "/dashboard",
        "/account/settings",
        "https://myapp.com/dashboard",
        "https://trusted-site.com/continue",
        "https://partner-domain.org/welcome",
    ]

    main_url = fdp.PickValueInList(main_urls)
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        target_param = fdp.PickValueInList(ATTACKS[family])
    else:
        target_param = fdp.PickValueInList(benign_targets)

    return {"main_url": main_url, "target_param": target_param}
