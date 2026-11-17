ATTACKS = {
    "allowlist_suffix_confusion": [
        "https://api.trustedsource.com.attacker.invalid/data",
        "https://evil.api.trustedsource.com/data",
        "https://gateway.partnerapi.com.evil.test/data",
    ],
    "userinfo_authority_confusion": [
        "https://api.trustedsource.com@127.0.0.1/secret",
        "https://gateway.partnerapi.com@169.254.169.254/latest/meta-data/",
        "https://attacker.invalid@api.trustedsource.com/data",
    ],
    "private_ipv4_and_metadata": [
        "http://127.0.0.1/secret",
        "http://127.0.0.2/secret",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0/",
    ],
    "noncanonical_ipv4": [
        "http://2130706433/secret",
        "http://0177.0.0.1/secret",
        "http://0x7f000001/secret",
        "http://127.1/secret",
    ],
    "ipv6_internal": [
        "http://[::1]/secret",
        "http://[::ffff:127.0.0.1]/secret",
        "http://[fe80::1]/secret",
    ],
    "internal_hostnames": [
        "http://localhost/secret",
        "http://localhost.localdomain/secret",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
    "parser_and_encoding_confusion": [
        "https://api.trustedsource.com%2e.attacker.invalid/data",
        "https://api.trustedsource.com\\@127.0.0.1/secret",
        "https://127.0.0.1#@api.trustedsource.com/secret",
        "http://127%2e0%2e0%2e1/secret",
    ],
    "untrusted_scheme": [
        "file://api.trustedsource.com/etc/passwd",
        "gopher://127.0.0.1:11211/_stats",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        url = fdp.PickValueInList(ATTACKS[family])
    else:
        trusted_urls = [
            "https://api.trustedsource.com/data",
            "https://gateway.partnerapi.com/v1/status",
            "http://api.trustedsource.com/health",
        ]
        url = fdp.PickValueInList(trusted_urls)
        suffix = fdp.ConsumeUnicodeNoSurrogates(12)
        if suffix:
            url += "?q=" + suffix
    return {"url_to_check": url}
