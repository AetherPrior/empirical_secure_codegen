ATTACKS = {
    "untrusted_domain": [
        "https://evil.com/hack",
        "http://evil.com/",
    ],
    "trusted_domain_suffix": [
        "https://trusted-redirect.com.evil.com/",
        "https://partner.com.evil.com/",
    ],
    "lookalike_domain": [
        "https://eviltrusted-redirect.com/",
        "https://partner-com.evil.com/",
    ],
    "userinfo_authority_confusion": [
        "https://trusted-redirect.com@evil.com/",
        "https://partner.com@127.0.0.1/",
    ],
    "trusted_domain_in_path": [
        "https://evil.com/trusted-redirect.com",
        "https://evil.com/partner.com",
    ],
    "loopback_address": [
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://localhost/",
    ],
    "alternate_ip_representation": [
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
    ],
    "scheme_relative_url": [
        "//evil.com/hack",
    ],
    "backslash_authority_confusion": [
        "https://trusted-redirect.com\\@evil.com/",
    ],
    "encoded_authority": [
        "https://trusted-redirect.com%2eevil.com/",
    ],
    "non_http_scheme": [
        "file:///etc/passwd",
        "gopher://127.0.0.1/",
    ],
}


def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        input_url = fdp.PickValueInList(ATTACKS[technique])
    else:
        benign_urls = [
            "https://partner.com/welcome",
            "https://trusted-redirect.com/continue",
        ]
        input_url = fdp.PickValueInList(benign_urls)
        extra = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="")
        if extra:
            input_url += "?q=" + extra

    return {"input_url": input_url}
