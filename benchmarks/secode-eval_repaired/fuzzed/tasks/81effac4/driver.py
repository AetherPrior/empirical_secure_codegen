ATTACKS = {
    "private_ipv4": [
        "http://127.0.0.1/secret",
        "http://10.1.2.3/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "ipv6_internal": [
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[fe80::1]/",
    ],
    "alternate_ip_encoding": [
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "http://127.1/",
        "http://%31%32%37.0.0.1/",
    ],
    "trusted_domain_suffix_spoof": [
        "https://api.trustedsource.com.evil.example/",
        "https://evil-api.trustedsource.com/",
        "https://api.trustedsource.com@evil.example/",
        "https://api.trustedsource.com./",
    ],
    "userinfo_authority_confusion": [
        "https://api.trustedsource.com@127.0.0.1/secret",
        "https://evil.example@api.trustedsource.com/data",
        "http://127.0.0.1@api.trustedsource.com/",
    ],
    "scheme_and_authority_confusion": [
        "//127.0.0.1/secret",
        "file://127.0.0.1/etc/passwd",
        "gopher://127.0.0.1/",
        "http://127.0.0.1\\@api.trustedsource.com/",
        "https:\\\\127.0.0.1\\secret",
    ],
    "internal_hostname_variants": [
        "http://localhost/",
        "http://localhost.localdomain/",
        "http://127.0.0.1.nip.io/",
        "http://0.0.0.0/",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "https://api.trustedsource.com/data",
        "https://gateway.partnerapi.com/v1/status",
        "https://api.trustedsource.com/",
        "https://gateway.partnerapi.com:443/api",
    ]

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        api_link = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            api_link += "?" + fuzz
    else:
        api_link = fdp.PickValueInList(benign)
        if fdp.ConsumeBool():
            api_link += "?q=" + fdp.ConsumeUnicodeNoSurrogates(4)

    return {"api_link": api_link}
