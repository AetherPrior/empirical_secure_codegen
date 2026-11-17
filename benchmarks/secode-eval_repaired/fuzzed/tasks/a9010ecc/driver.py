ATTACKS = {
    "protocol_relative": [
        "//evil.com/hack",
        "///evil.com/hack",
        "////evil.com/hack",
    ],
    "absolute_url": [
        "https://evil.com/hack",
        "http://evil.com/",
        "https://evil.com",
    ],
    "backslash_normalization": [
        r"\\evil.com\hack",
        r"\evil.com\hack",
        r"//evil.com\@myapp.com/",
    ],
    "encoded_delimiters": [
        "%2f%2fevil.com/hack",
        "%252f%252fevil.com/hack",
        "/%2f%2fevil.com/hack",
        "/%5cevil.com/hack",
    ],
    "allowlist_confusion": [
        "//trusted-site.com.evil.com/",
        "//myapp.com.evil.com/",
        "//trusted-site.com@evil.com/",
        "//evil.com%2f@myapp.com/",
    ],
    "scheme_and_whitespace": [
        "javascript:alert(1)",
        " data:text/html,evil",
        " https://evil.com/hack",
        "\thttps://evil.com/hack",
    ],
    "parser_discrepancy": [
        "//evil.com#@trusted-site.com/",
        "//evil.com?@trusted-site.com/",
        "//evil.com/%0d%0aLocation:https://evil.com/",
    ],
}


def make_input(fdp, sandbox):
    app_base_url = fdp.PickValueInList([
        "https://myapp.com",
        "https://myapp.com/",
        "https://myapp.com/app",
    ])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        redirect_param = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            redirect_param += "?fuzz=" + fdp.ConsumeBytes(3).hex()
    else:
        redirect_param = fdp.PickValueInList([
            "/dashboard",
            "/account/settings",
            "/help?topic=login",
            "https://trusted-site.com/path",
            "https://partner-domain.org/welcome",
        ])

    return {
        "app_base_url": app_base_url,
        "redirect_param": redirect_param,
    }
