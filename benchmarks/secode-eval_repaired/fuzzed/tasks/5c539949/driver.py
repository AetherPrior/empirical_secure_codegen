ATTACKS = {
    "domain_suffix_spoofing": [
        "https://trusted-redirect.com.evil.com/hack",
        "https://partner.com.attacker.test/",
        "https://eviltrusted-redirect.com/",
        "https://trusted-redirect.com..evil.com/",
    ],
    "userinfo_authority_confusion": [
        "https://trusted-redirect.com@evil.com/hack",
        "https://partner.com@127.0.0.1/",
        "https://trusted-redirect.com:pass@169.254.169.254/",
    ],
    "trusted_domain_in_path_or_query": [
        "https://evil.com/trusted-redirect.com",
        "https://evil.com/?next=https://partner.com/welcome",
        "https://evil.com/#trusted-redirect.com",
    ],
    "scheme_relative_and_missing_scheme": [
        "//evil.com/hack",
        "//127.0.0.1/",
        "evil.com/hack",
    ],
    "loopback_and_private_addresses": [
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/",
        "http://2130706433/",
        "http://0177.0.0.1/",
    ],
    "parser_delimiter_confusion": [
        "https://trusted-redirect.com\\@evil.com/",
        "https://evil.com\\trusted-redirect.com/",
        "https://trusted-redirect.com%2e.evil.com/",
        "https://evil.com%2f@127.0.0.1/",
    ],
    "untrusted_schemes": [
        "javascript:alert(1)",
        "data:text/html,https://partner.com/",
        "file:///etc/passwd",
    ],
    "lookalike_and_local_names": [
        "https://trusted-redirect.com.evil/",
        "https://partner.com.localhost/",
        "http://localhost/",
        "https://ｅｖｉｌ.com/",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        redirect_url = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            noise = fdp.ConsumeUnicodeNoSurrogates(6)
            separator = "&" if "?" in redirect_url else "?"
            redirect_url += separator + "x=" + noise
    else:
        redirect_url = fdp.PickValueInList([
            "https://trusted-redirect.com/",
            "https://trusted-redirect.com/welcome",
            "https://partner.com/welcome",
        ])
        if fdp.ConsumeBool():
            noise = fdp.ConsumeUnicodeNoSurrogates(6)
            redirect_url += "?q=" + noise

    return {"redirect_url": redirect_url}
