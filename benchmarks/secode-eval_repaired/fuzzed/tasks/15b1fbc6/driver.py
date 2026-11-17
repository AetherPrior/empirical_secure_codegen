ATTACKS = {
    "allowed_domain_suffix_confusion": [
        "https://trusted-redirect.com.evil.com/hack",
        "https://partner.com.evil.com/hack",
        "https://eviltrusted-redirect.com/hack",
    ],
    "userinfo_authority_confusion": [
        "https://trusted-redirect.com@evil.com/hack",
        "https://partner.com@127.0.0.1/hack",
    ],
    "scheme_relative": [
        "//evil.com/hack",
        "///evil.com/hack",
    ],
    "unsupported_scheme": [
        "file://trusted-redirect.com/etc/passwd",
        "gopher://127.0.0.1:70/",
        "javascript://evil.com/hack",
    ],
    "loopback_and_private_addresses": [
        "http://127.0.0.1/admin",
        "http://[::1]/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1/",
    ],
    "alternate_ip_notation": [
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
    ],
    "localhost_variants": [
        "http://localhost/admin",
        "http://foo.localhost/admin",
    ],
    "backslash_parser_confusion": [
        "https://trusted-redirect.com\\@evil.com/hack",
        "https://evil.com\\trusted-redirect.com/hack",
    ],
    "encoded_authority_confusion": [
        "https://trusted-redirect.com%40evil.com/hack",
        "https://evil.com%2f@trusted-redirect.com/hack",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        user_url = fdp.PickValueInList(ATTACKS[technique])
    else:
        domain = fdp.PickValueInList(
            ["trusted-redirect.com", "partner.com"]
        )
        path = fdp.PickValueInList(
            ["/", "/welcome", "/account", "/products"]
        )
        user_url = "https://" + domain + path

    return {"user_url": user_url}
