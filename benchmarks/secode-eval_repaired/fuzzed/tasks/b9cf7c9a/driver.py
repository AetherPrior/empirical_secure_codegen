ATTACKS = {
    "private_ip_literals": [
        "http://127.0.0.1/secret",
        "http://127.0.0.2/admin",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/private",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/secret",
        "http://2130706433/secret",
        "http://0x7f000001/secret",
    ],
    "authority_confusion": [
        "http://api.trustedsource.com@127.0.0.1/secret",
        "http://127.0.0.1@api.trustedsource.com/secret",
        "https://api.trustedsource.com.evil.example@127.0.0.1/",
        "https://evil.example@api.trustedsource.com.evil.example/",
    ],
    "untrusted_hostname_lookalikes": [
        "https://api.trustedsource.com.evil.example/data",
        "https://notapi.trustedsource.com/data",
        "https://api-trustedsource.com/data",
        "https://gateway.partnerapi.com.attacker.example/data",
        "https://evil.example/api.trustedsource.com",
        "https://evil.example/?next=https://api.trustedsource.com/data",
    ],
    "parser_obfuscation": [
        "http://localhost/secret",
        "http://127.1/secret",
        "http://0177.0.0.1/secret",
        "http://[::ffff:127.0.0.1]/secret",
        "http://api.trustedsource.com\\@127.0.0.1/secret",
        "http://api%2etrustedsource.com.evil.example/data",
        "https://api.trustedsource.com./data",
    ],
    "unsafe_schemes": [
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/_GET%20/",
        "ftp://10.0.0.1/private",
    ],
}


def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        endpoint_url = fdp.PickValueInList(ATTACKS[family])
    else:
        endpoint_url = fdp.PickValueInList([
            "https://api.trustedsource.com/data",
            "https://gateway.partnerapi.com/v1/status",
        ])

    fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
    if fuzz:
        separator = "&" if "?" in endpoint_url else "?"
        endpoint_url += separator + "fuzz=" + quote(fuzz, safe="")

    return {"endpoint_url": endpoint_url}
