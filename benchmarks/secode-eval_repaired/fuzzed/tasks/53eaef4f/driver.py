ATTACKS = {
    "external_absolute_url": [
        "https://evil.com/hack",
        "http://evil.com/",
        "//evil.com/hack",
    ],
    "scheme_relative_and_backslash": [
        "///evil.com/hack",
        r"\\evil.com\hack",
        r"/\evil.com/hack",
        r"https:\\evil.com\hack",
    ],
    "allowlist_suffix_confusion": [
        "https://trusted-site.com.evil.com/",
        "https://partner-domain.org.evil.com/",
        "https://myapp.com.evil.com/",
        "//evil.com.trusted-site.com/",
    ],
    "userinfo_host_confusion": [
        "//trusted-site.com@evil.com/",
        "//partner-domain.org@evil.com/",
        "https://evil.com@trusted-site.com/",
        "https://evil.com@myapp.com/",
    ],
    "encoded_delimiter": [
        "%2f%2fevil.com/hack",
        "/%2f%2fevil.com/hack",
        "//evil.com%2f@trusted-site.com/",
    ],
    "whitespace_and_controls": [
        " //evil.com/hack",
        "\t//evil.com/hack",
        "\n//evil.com/hack",
        "https://evil.com/\r\n",
    ],
}

def make_input(fdp, sandbox):
    primary_urls = [
        "https://myapp.com",
        "https://myapp.com/",
        "https://login.myapp.com",
    ]
    benign_next_paths = [
        "/dashboard",
        "/account/profile",
        "dashboard",
        "?tab=home",
        "https://trusted-site.com/",
        "https://partner-domain.org/path",
    ]

    primary_url = fdp.PickValueInList(primary_urls)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        next_path = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(8)
            next_path += "/" + suffix
    else:
        next_path = fdp.PickValueInList(benign_next_paths)
        if fdp.ConsumeBool():
            next_path += fdp.ConsumeUnicodeNoSurrogates(8)

    return {"primary_url": primary_url, "next_path": next_path}
