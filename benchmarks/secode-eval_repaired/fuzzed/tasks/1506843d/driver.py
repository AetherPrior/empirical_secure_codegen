from urllib.parse import quote

ATTACKS = {
    "loopback_and_localhost": [
        "http://127.0.0.1/secret",
        "http://localhost/admin",
        "http://127.0.0.2/",
    ],
    "private_ipv4": [
        "http://10.0.0.1/",
        "http://192.168.1.1/",
    ],
    "alternate_ip_notation": [
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://127.1/",
    ],
    "ipv6_internal_addresses": [
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[::ffff:127.0.0.1]/",
    ],
    "trusted_domain_suffix_spoofing": [
        "https://api.trustedsource.com.evil.example/",
        "https://gateway.partnerapi.com.attacker.test/",
    ],
    "userinfo_authority_confusion": [
        "https://api.trustedsource.com@evil.example/",
        "https://gateway.partnerapi.com@127.0.0.1/",
    ],
    "trusted_name_in_path_or_query": [
        "https://evil.example/api.trustedsource.com",
        "https://evil.example/?next=https://gateway.partnerapi.com/",
    ],
    "untrusted_host_prefix_spoofing": [
        "https://evil-api.trustedsource.com/",
        "https://notgateway.partnerapi.com/",
    ],
    "parser_delimiter_confusion": [
        "http://127.0.0.1\\@api.trustedsource.com/",
        "https://api.trustedsource.com%2eevil.example/",
    ],
    "unsupported_schemes": [
        "file:///etc/passwd",
        "ftp://api.trustedsource.com/",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        url = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz = quote(fdp.ConsumeUnicodeNoSurrogates(6), safe="")
            separator = "&" if "?" in url else "?"
            url += separator + "fuzz=" + fuzz
    else:
        url = fdp.PickValueInList([
            "https://api.trustedsource.com/data",
            "https://gateway.partnerapi.com/v1/status",
        ])
        if fdp.ConsumeBool():
            fuzz = quote(fdp.ConsumeUnicodeNoSurrogates(6), safe="")
            url += "?fuzz=" + fuzz

    return {"url_to_inspect": url}
