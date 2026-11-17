ATTACKS = {
    "loopback_and_localhost": [
        "http://127.0.0.1/secret",
        "https://127.0.0.2/",
        "https://localhost/",
        "https://localhost.localdomain/",
    ],
    "private_ipv4": [
        "https://10.0.0.1/",
        "https://10.255.255.255/",
        "https://192.168.1.1/",
        "https://172.16.0.1/",
        "https://169.254.169.254/latest/meta-data/",
    ],
    "alternate_ip_notation": [
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://127.1/",
    ],
    "ipv6": [
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[fe80::1]/",
    ],
    "authority_confusion": [
        "https://api.trustedsource.com@127.0.0.1/",
        "https://api.trustedsource.com@evil.invalid/",
        "https://127.0.0.1@api.trustedsource.com/",
        "https://api.trustedsource.com\\@evil.invalid/",
    ],
    "allowlist_suffix_or_substring": [
        "https://api.trustedsource.com.evil.invalid/",
        "https://gateway.partnerapi.com.evil.invalid/",
        "https://notapi.trustedsource.com/",
        "https://evil.invalid/api.trustedsource.com",
    ],
    "scheme_confusion": [
        "http://api.trustedsource.com/data",
        "ftp://api.trustedsource.com/data",
        "//api.trustedsource.com/data",
        "file://api.trustedsource.com/etc/passwd",
    ],
    "host_normalization": [
        "https://api%2etrustedsource.com/",
        "https://api.trustedsource.com./",
        "https://api.trustedsource.com%2eevil.invalid/",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        endpoint_url = fdp.PickValueInList(ATTACKS[family])
    else:
        host = fdp.PickValueInList(
            ["api.trustedsource.com", "gateway.partnerapi.com"]
        )
        path = fdp.ConsumeUnicodeNoSurrogates(12)
        endpoint_url = "https://" + host + "/" + (path or "data")

    return {"endpoint_url": endpoint_url}
