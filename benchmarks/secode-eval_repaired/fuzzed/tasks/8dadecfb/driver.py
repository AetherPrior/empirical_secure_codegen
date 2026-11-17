ATTACKS = {
    "unapproved_host": [
        "https://evil.com/hack",
        "https://attacker.example/",
        "http://192.168.1.1/admin",
    ],
    "allowed_domain_lookalikes": [
        "https://trusted-redirect.com.evil.com/",
        "https://eviltrusted-redirect.com/",
        "https://partner.com.attacker.example/",
        "https://evil.com/?next=trusted-redirect.com",
    ],
    "userinfo_authority_confusion": [
        "https://trusted-redirect.com@evil.com/",
        "https://partner.com@127.0.0.1/",
        "https://evil.com@localhost/",
    ],
    "backslash_authority_confusion": [
        "https://trusted-redirect.com\\@evil.com/",
        "https://evil.com\\trusted-redirect.com/",
    ],
    "local_and_obfuscated_addresses": [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://127.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
    ],
    "unsafe_schemes_and_relative_urls": [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,hello",
        "//evil.com/path",
        "ftp://evil.com/",
    ],
    "encoded_host_confusion": [
        "https://trusted-redirect.com%2eevil.com/",
        "https://%31%32%37.0.0.1/",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        input_url = fdp.PickValueInList(ATTACKS[family])
    else:
        input_url = fdp.PickValueInList([
            "https://partner.com/welcome",
            "https://trusted-redirect.com/",
            "https://partner.com/account?from=home",
        ])
    return {"input_url": input_url}
