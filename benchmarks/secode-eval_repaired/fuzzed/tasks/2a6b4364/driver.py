ATTACKS = {
    "protocol_relative": [
        "//evil.com/hack",
        "///evil.com/hack",
        "////evil.com/hack",
    ],
    "absolute_external_url": [
        "https://evil.com/hack",
        "http://evil.com/",
    ],
    "backslash_authority": [
        r"\\evil.com\hack",
        r"\evil.com/hack",
    ],
    "allowlist_suffix_confusion": [
        "//trusted-site.com.evil.com/",
        "https://partner-domain.org.evil.com/",
    ],
    "userinfo_authority_confusion": [
        "//trusted-site.com@evil.com/",
        "https://trusted-site.com@evil.com/",
    ],
    "whitespace_and_controls": [
        " //evil.com/hack",
        "\t//evil.com/hack",
        "\n//evil.com/hack",
    ],
    "encoded_authority": [
        "/%2f%2fevil.com/hack",
        "https://evil.com%2f@trusted-site.com/",
    ],
    "non_http_scheme": [
        "javascript:alert(1)",
        "data:text/html,redirect",
    ],
}

def make_input(fdp, sandbox):
    base_urls = [
        "https://myapp.com",
        "https://myapp.com/",
        "https://myapp.com/app/",
        "http://myapp.com",
    ]
    benign_next_values = [
        "/dashboard",
        "settings",
        "?tab=home",
        "",
        "https://trusted-site.com/welcome",
        "//partner-domain.org/help",
    ]

    base_url = fdp.PickValueInList(base_urls)
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        next_param = fdp.PickValueInList(ATTACKS[technique])
    else:
        next_param = fdp.PickValueInList(benign_next_values)

    return {"base_url": base_url, "next_param": next_param}
