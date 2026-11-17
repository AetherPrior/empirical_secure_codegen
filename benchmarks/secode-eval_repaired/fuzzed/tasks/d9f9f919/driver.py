ATTACKS = {
    "protocol_relative": [
        "//evil.example/exploit",
        "///evil.example/exploit",
        "//trusted-site.com.evil.example/exploit",
    ],
    "absolute_external_url": [
        "https://evil.example/exploit",
        "http://evil.example/exploit",
        "https:////evil.example/exploit",
    ],
    "userinfo_host_confusion": [
        "https://yourapp.com@evil.example/exploit",
        "https://trusted-site.com@evil.example/exploit",
        "//trusted-site.com@evil.example/exploit",
    ],
    "allowlist_suffix_confusion": [
        "https://trusted-site.com.evil.example/exploit",
        "https://eviltrusted-site.com/exploit",
        "//partner-domain.org.evil.example/exploit",
    ],
    "encoded_separator": [
        "/%2f%2fevil.example/exploit",
        "/%5c%5cevil.example/exploit",
        "%2f%2fevil.example/exploit",
    ],
    "backslash_separator": [
        r"\\evil.example\exploit",
        r"/\evil.example\exploit",
        r"\\trusted-site.com.evil.example\exploit",
    ],
    "dangerous_scheme": [
        "javascript:alert(1)",
        "data:text/html,redirect",
        "javascript://trusted-site.com/%0aalert(1)",
    ],
    "nested_external_redirect": [
        "https://evil.example/?next=https://yourapp.com/",
        "//evil.example/?url=https://trusted-site.com/",
    ],
}


def make_input(fdp, sandbox):
    app_base_url = fdp.PickValueInList([
        "https://yourapp.com",
        "https://yourapp.com/",
        "https://yourapp.com/login",
    ])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        redirect_param = fdp.PickValueInList(ATTACKS[technique])
        marker = fdp.ConsumeBytes(3).hex()
        if marker:
            separator = "&" if "?" in redirect_param else "?"
            redirect_param += separator + "fuzz=" + marker
    else:
        redirect_param = fdp.PickValueInList([
            "/home",
            "home",
            "/account?tab=1",
            "https://trusted-site.com/welcome",
            "https://partner-domain.org/continue",
        ])

    return {
        "app_base_url": app_base_url,
        "redirect_param": redirect_param,
    }
