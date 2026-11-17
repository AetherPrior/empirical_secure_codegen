ATTACKS = {
    "loopback_and_private_ipv4": [
        "http://127.0.0.1/secret",
        "https://10.0.0.1/admin",
        "https://192.168.1.1/",
        "https://localhost/",
    ],
    "alternate_ip_notations": [
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "http://127.1/",
    ],
    "ipv6_internal_addresses": [
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[fc00::1]/",
    ],
    "trusted_domain_suffix_confusion": [
        "https://api.trustedsource.com.evil.example/data",
        "https://evil-api.trustedsource.com/data",
        "https://gateway.partnerapi.com.attacker.example/",
    ],
    "userinfo_host_confusion": [
        "https://api.trustedsource.com@127.0.0.1/secret",
        "https://gateway.partnerapi.com@localhost/admin",
        "https://attacker.example@api.trustedsource.com/data",
    ],
    "scheme_bypass": [
        "http://api.trustedsource.com/data",
        "ftp://api.trustedsource.com/data",
        "file://api.trustedsource.com/etc/passwd",
        "//api.trustedsource.com/data",
    ],
    "parser_and_encoding_confusion": [
        "https://api.trustedsource.com\\@127.0.0.1/",
        "https://%61pi.trustedsource.com/data",
        "https://api.trustedsource.com./data",
        "https://api.trustedsource.com%2eattacker.example/data",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        api_url = fdp.PickValueInList(ATTACKS[family])
    else:
        api_url = fdp.PickValueInList([
            "https://api.trustedsource.com/data",
            "https://gateway.partnerapi.com/v1/status",
        ])

    return {"api_url": api_url}
