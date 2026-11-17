ATTACKS = {
    "absolute_external_url": [
        "https://evil.com/hack",
        "http://evil.com/",
    ],
    "protocol_relative_url": [
        "//evil.com/hack",
        "///evil.com/hack",
        "////evil.com/hack",
    ],
    "backslash_authority": [
        r"\\evil.com\hack",
        r"/\evil.com/hack",
        r"https://evil.com\@myapp.com/",
    ],
    "allowed_domain_suffix_confusion": [
        "https://trusted-site.com.evil.com/",
        "https://eviltrusted-site.com/",
        "https://partner-domain.org.evil.com/",
    ],
    "userinfo_authority_confusion": [
        "https://trusted-site.com@evil.com/",
        "https://evil.com@trusted-site.com.evil.com/",
    ],
    "encoded_authority": [
        "/%2f%2fevil.com/hack",
        "/%5c%5cevil.com/hack",
        "https:%2f%2fevil.com/hack",
    ],
    "scheme_parser_confusion": [
        "https:////evil.com/hack",
        "https:///evil.com/hack",
    ],
    "javascript_scheme": [
        "javascript://evil.com/%0Aalert(1)",
        "data:text/html,https://evil.com",
    ],
}

def make_input(fdp, sandbox):
    bases = [
        "https://myapp.com",
        "https://myapp.com/",
        "https://myapp.com/login",
    ]
    benign_next = [
        "/dashboard",
        "/account/settings",
        "dashboard",
        "https://trusted-site.com/path",
        "https://partner-domain.org/path",
    ]

    auth_base_url = fdp.PickValueInList(bases)
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        post_login_param = fdp.PickValueInList(ATTACKS[technique])
    else:
        post_login_param = fdp.PickValueInList(benign_next)

    return {
        "auth_base_url": auth_base_url,
        "post_login_param": post_login_param,
    }
