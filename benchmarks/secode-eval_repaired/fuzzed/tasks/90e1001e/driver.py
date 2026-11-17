ATTACKS = {
    "private_ipv4": [
        "http://127.0.0.1/secret",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "alternate_ip_notation": [
        "http://127.1/",
        "http://2130706433/",
        "http://0x7f000001/",
    ],
    "ipv6_internal": [
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
    ],
    "localhost": [
        "http://localhost/",
        "http://localhost.localdomain/",
    ],
    "allowlist_suffix_or_prefix": [
        "https://api.trustedsource.com.evil.example/",
        "https://gateway.partnerapi.com.evil.example/",
        "https://evil-api.trustedsource.com/",
    ],
    "userinfo_authority_confusion": [
        "http://api.trustedsource.com@127.0.0.1/",
        "https://gateway.partnerapi.com@169.254.169.254/",
    ],
    "encoded_or_trailing_host": [
        "https://api.trustedsource.com%2eevil.example/",
        "https://api.trustedsource.com./",
    ],
    "parser_and_scheme_confusion": [
        "http://api.trustedsource.com\\@127.0.0.1/",
        "file://api.trustedsource.com/secret",
        "gopher://127.0.0.1/",
    ],
}


def make_input(fdp, sandbox):
    from urllib.parse import quote

    benign_urls = [
        "https://api.trustedsource.com/data",
        "https://gateway.partnerapi.com/v1/status",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        service_url = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            extra = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="")
            separator = "&" if "?" in service_url else "?"
            service_url += separator + "probe=" + extra
    else:
        service_url = fdp.PickValueInList(benign_urls)
        if fdp.ConsumeBool():
            extra = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="")
            separator = "&" if "?" in service_url else "?"
            service_url += separator + "probe=" + extra

    return {"service_url": service_url}
