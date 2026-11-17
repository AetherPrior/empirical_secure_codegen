ATTACKS = {
    "loopback": [
        "http://127.0.0.1/secret",
        "http://127.0.0.2/",
        "http://localhost/",
        "http://127.1/",
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
    ],
    "private_network": [
        "http://10.0.0.1/",
        "http://10.255.255.254/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
    ],
    "untrusted_host": [
        "http://evil.example/",
        "http://api.trustedsource.com.evil.example/",
        "http://evilapi.trustedsource.com/",
        "http://trustedsource.com/",
        "http://api.trustedsource.com./",
        "http://api。trustedsource.com/",
    ],
    "userinfo_authority_confusion": [
        "http://api.trustedsource.com@evil.example/",
        "http://evil.example@api.trustedsource.com/",
        "http://api.trustedsource.com@127.0.0.1/",
        "http://127.0.0.1@api.trustedsource.com/",
        "http://evil.example:80@10.0.0.1/",
    ],
    "parser_discrepancy": [
        "http://127.0.0.1\\@api.trustedsource.com/",
        "http://api.trustedsource.com\\@evil.example/",
        "http://%31%32%37.0.0.1/",
        "http://127.0.0.1%2f@api.trustedsource.com/",
        "//127.0.0.1/secret",
        "http:////127.0.0.1/secret",
        "http://api.trustedsource.com%2eevil.example/",
    ],
    "scheme_and_port": [
        "file://127.0.0.1/etc/passwd",
        "ftp://api.trustedsource.com/",
        "gopher://127.0.0.1/",
        "http://api.trustedsource.com:8080/",
        "https://api.trustedsource.com:1/",
        "http://10.0.0.1:443/",
    ],
    "malformed_or_ambiguous_url": [
        "http://127.0.0.1%00.evil.example/",
        "http://127.0.0.1./",
        "http://127.000.000.001/",
        "http://10.1.2.999/",
        "http://[::1",
        "http://",
        "http://api.trustedsource.com\n@evil.example/",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        url = fdp.PickValueInList(ATTACKS[technique])
    else:
        url = fdp.PickValueInList([
            "https://api.trustedsource.com/data",
            "https://gateway.partnerapi.com/v1/status",
            "https://api.trustedsource.com/",
            "https://gateway.partnerapi.com:443/api",
        ])

    if fdp.ConsumeBool():
        suffix = fdp.ConsumeUnicodeNoSurrogates(8)
        if suffix:
            url += suffix

    return {"url_to_check": url}
