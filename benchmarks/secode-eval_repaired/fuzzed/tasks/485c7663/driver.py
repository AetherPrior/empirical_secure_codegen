ATTACKS = {
    "direct_internal_hosts": [
        "http://127.0.0.1/secret",
        "https://localhost/admin",
        "http://10.1.2.3/internal",
        "http://192.168.1.10/private",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
    "allowlist_suffix_and_prefix_confusion": [
        "https://api.trustedsource.com.evil.example/data",
        "https://evil-api.trustedsource.com/data",
        "https://gateway.partnerapi.com.attacker.test/data",
        "https://notapi.trustedsource.com/data",
    ],
    "userinfo_authority_confusion": [
        "https://api.trustedsource.com@127.0.0.1/secret",
        "https://gateway.partnerapi.com@10.0.0.1/internal",
        "https://127.0.0.1@api.trustedsource.com/data",
        "https://evil.example#@api.trustedsource.com/",
    ],
    "alternate_ip_encodings": [
        "http://2130706433/secret",
        "http://0177.0.0.1/secret",
        "http://0x7f000001/secret",
        "http://127.1/secret",
        "http://[::1]/secret",
        "http://[::ffff:127.0.0.1]/secret",
    ],
    "internal_hostname_variants": [
        "http://localhost./secret",
        "http://localhost.localdomain/secret",
        "http://127.0.0.1.nip.io/secret",
        "http://0.0.0.0/secret",
    ],
    "scheme_and_parser_confusion": [
        "//127.0.0.1/secret",
        "https:////127.0.0.1/secret",
        "http://api.trustedsource.com:443@127.0.0.1/secret",
        "https://api.trustedsource.com\\@127.0.0.1/secret",
        "file://api.trustedsource.com/etc/passwd",
    ],
    "approved_host_with_insecure_scheme": [
        "http://api.trustedsource.com/data",
        "ftp://gateway.partnerapi.com/data",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "https://api.trustedsource.com/data",
        "https://gateway.partnerapi.com/v1/status",
        "https://API.TRUSTEDSOURCE.COM/data",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        endpoint = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            extra = fdp.ConsumeUnicodeNoSurrogates(8)
            endpoint += "?probe=" + extra
    else:
        endpoint = fdp.PickValueInList(benign)
        if fdp.ConsumeBool():
            endpoint += "?q=" + fdp.ConsumeUnicodeNoSurrogates(8)

    return {"api_endpoint": endpoint}
