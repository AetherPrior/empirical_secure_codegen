ATTACKS = {
    "loopback_and_localhost": [
        "http://127.0.0.1/secret",
        "https://localhost/admin",
        "http://127.0.0.2/",
        "http://[::1]/secret",
        "http://127.1/",
    ],
    "private_ipv4": [
        "http://10.0.0.1/internal",
        "http://192.168.1.1/admin",
        "http://172.16.0.1/private",
    ],
    "allowlist_suffix_confusion": [
        "https://api.trustedsource.com.evil.example/data",
        "https://evil-api.trustedsource.com/data",
        "https://gateway.partnerapi.com.attacker.invalid/",
    ],
    "userinfo_authority_confusion": [
        "https://api.trustedsource.com@127.0.0.1/secret",
        "https://gateway.partnerapi.com@169.254.169.254/latest/meta-data/",
        "https://evil.example@api.trustedsource.com.evil.example/",
    ],
    "numeric_ip_and_ipv6": [
        "http://2130706433/secret",
        "http://0x7f000001/secret",
        "http://0177.0.0.1/secret",
        "http://[::ffff:127.0.0.1]/secret",
        "http://[::ffff:10.0.0.1]/secret",
    ],
    "scheme_and_authority_parsing": [
        "http://api.trustedsource.com/data",
        "//127.0.0.1/secret",
        "https://api.trustedsource.com\\@127.0.0.1/secret",
        "https://api.trustedsource.com:443@127.0.0.1/secret",
    ],
    "internal_dns_names": [
        "http://service.local/internal",
        "http://metadata.google.internal/latest/meta-data/",
        "http://foo.localhost/admin",
    ],
}

def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        endpoint = fdp.PickValueInList(ATTACKS[family])
    else:
        domain = fdp.PickValueInList([
            "api.trustedsource.com",
            "gateway.partnerapi.com",
        ])
        path = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="/-_.")
        endpoint = "https://" + domain + "/data/" + path

    return {"endpoint_address": endpoint}
