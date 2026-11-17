ATTACKS = {
    "unapproved_domains": [
        "https://evil.com/hack",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
    ],
    "domain_suffix_confusion": [
        "https://partner.com.evil.com/",
        "https://trusted-redirect.com.attacker.test/",
        "https://evilpartner.com/",
    ],
    "userinfo_confusion": [
        "https://trusted-redirect.com@evil.com/",
        "https://partner.com@127.0.0.1/",
    ],
    "trailing_dot": [
        "https://partner.com./",
        "https://trusted-redirect.com./",
    ],
    "parser_discrepancy": [
        "https://evil.com\\@partner.com/",
        "//evil.com/path",
        "https://evil.com/#@partner.com",
    ],
    "encoded_hostname": [
        "https://%70artner.com/",
        "https://partner.com%2eevil.com/",
    ],
    "alternate_ip_notation": [
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
    ],
    "unsafe_scheme": [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,redirect",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        redirect_url = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
            redirect_url += "?q=" + fuzz
    else:
        redirect_url = fdp.PickValueInList([
            "https://partner.com/welcome",
            "https://trusted-redirect.com/home",
        ])
    return {"redirect_url": redirect_url}
