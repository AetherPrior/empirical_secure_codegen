ATTACKS = {
    "untrusted_domain": [
        "https://evil.com/hack",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://2130706433/",
        "http://0x7f000001/",
    ],
    "suffix_and_subdomain_confusion": [
        "https://trusted-redirect.com.evil.com/",
        "https://evil-trusted-redirect.com/",
        "https://partner.com.evil.com/",
    ],
    "userinfo_confusion": [
        "https://trusted-redirect.com@evil.com/",
        "https://partner.com@evil.com/",
        "https://partner.com:443@evil.com/",
    ],
    "encoding_and_normalization": [
        "https://partner.com%2eevil.com/",
        "https://partner.com./",
        "https://PARTNER.COM.evil.com/",
    ],
    "parser_delimiter_confusion": [
        "https://evil.com#@partner.com/",
        "https://evil.com?next=https://partner.com/",
        "https:\\\\evil.com\\path",
        "//evil.com/path",
    ],
    "unsafe_scheme": [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "gopher://127.0.0.1/",
    ],
}


def make_input(fdp, sandbox):
    benign = [
        "https://partner.com/welcome",
        "https://trusted-redirect.com/",
    ]

    if not fdp.ConsumeBool():
        return {"input_url": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    # Optionally add a small fuzz-controlled fragment without changing the URL's authority.
    if fdp.ConsumeBool():
        payload += "#fuzz=" + fdp.ConsumeUnicodeNoSurrogates(6)

    return {"input_url": payload}
