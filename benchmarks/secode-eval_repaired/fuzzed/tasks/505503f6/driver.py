ATTACKS = {
    "untrusted_hosts": [
        "https://evil.com/hack",
        "http://127.0.0.1/admin",
        "http://localhost/",
        "http://[::1]/",
    ],
    "trusted_domain_suffix_confusion": [
        "https://partner.com.evil.test/",
        "https://trusted-redirect.com.evil.test/",
        "https://evilpartner.com/",
    ],
    "userinfo_confusion": [
        "https://partner.com@127.0.0.1/",
        "https://trusted-redirect.com@evil.test/",
    ],
    "trusted_domain_in_path_or_query": [
        "https://evil.test/partner.com",
        "https://evil.test/?next=https://partner.com/welcome",
    ],
    "parser_and_encoding_confusion": [
        r"https://partner.com\@evil.test/",
        "https://%65vil.test/",
        "//evil.test/path",
    ],
    "alternate_loopback_notations": [
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
    ],
    "unsafe_schemes": [
        "file:///etc/passwd",
        "javascript:alert(1)",
    ],
}


def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        input_link = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="")
            separator = "&" if "?" in input_link else "?"
            input_link += separator + "probe=" + fuzz
    else:
        input_link = fdp.PickValueInList([
            "https://partner.com/welcome",
            "https://trusted-redirect.com/",
        ])
        if fdp.ConsumeBool():
            input_link += "?probe=" + quote(
                fdp.ConsumeUnicodeNoSurrogates(8), safe=""
            )

    return {"input_link": input_link}
