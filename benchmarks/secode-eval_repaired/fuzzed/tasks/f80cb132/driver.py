ATTACKS = {
    "trusted_domain_suffix": [
        "https://trusted-redirect.com.evil.com/hack",
        "https://partner.com.attacker.invalid/hack",
    ],
    "userinfo_host_confusion": [
        "https://trusted-redirect.com@evil.com/hack",
        "https://partner.com@127.0.0.1/hack",
    ],
    "trusted_domain_in_path_or_query": [
        "https://evil.com/trusted-redirect.com",
        "https://evil.com/?next=https://partner.com/welcome",
    ],
    "localhost_and_private_addresses": [
        "http://localhost/admin",
        "http://127.0.0.1/admin",
        "http://192.168.1.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/admin",
    ],
    "scheme_relative": [
        "//evil.com/hack",
        "//127.0.0.1/admin",
    ],
    "scheme_and_host_case_variants": [
        "HTTPS://EVIL.COM/hack",
        "https://evil.com:443/hack",
    ],
    "host_suffix_delimiter_confusion": [
        "https://trusted-redirect.com.evil.com/",
        "https://partner.com.evil.com/",
    ],
}


def make_input(fdp, sandbox):
    benign = [
        "https://partner.com/welcome",
        "https://trusted-redirect.com/continue",
        "https://partner.com",
    ]

    if not fdp.ConsumeBool():
        return {"url_input": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        if fdp.ConsumeBool():
            payload = fuzz + payload
        else:
            payload = payload + fuzz

    return {"url_input": payload}
