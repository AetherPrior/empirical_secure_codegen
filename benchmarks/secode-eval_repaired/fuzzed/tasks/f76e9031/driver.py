ATTACKS = {
    "unapproved_hosts": [
        "https://evil.com/hack",
        "https://attacker.example/",
        "http://evil.com/",
    ],
    "suffix_confusion": [
        "https://trusted-redirect.com.evil.com/",
        "https://partner.com.attacker.example/",
        "https://eviltrusted-redirect.com/",
    ],
    "subdomain_confusion": [
        "https://evil.trusted-redirect.com/",
        "https://attacker.partner.com/",
    ],
    "userinfo_confusion": [
        "https://trusted-redirect.com@evil.com/",
        "https://partner.com@127.0.0.1/",
        "https://user:pass@evil.com/",
    ],
    "localhost_and_private_ips": [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://[::1]/",
        "http://2130706433/",
    ],
    "scheme_confusion": [
        "//evil.com/",
        "http:////evil.com/",
        "https:evil.com/",
        "javascript:alert(1)",
        "file:///etc/passwd",
    ],
    "parser_delimiter_confusion": [
        "https://trusted-redirect.com\\\\@evil.com/",
        "https://trusted-redirect.com%2e.evil.com/",
        "https://trusted-redirect.com%00.evil.com/",
    ],
    "hostname_normalization": [
        "https://trusted-redirect.com./",
        "https://TRUSTED-REDIRECT.COM.evil.com/",
        "https://partner。com.evil.com/",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        target_url = fdp.PickValueInList(ATTACKS[family])
    else:
        benign_urls = [
            "https://partner.com/welcome",
            "https://trusted-redirect.com/continue",
            "https://partner.com/",
        ]
        target_url = fdp.PickValueInList(benign_urls)

    return {"target_url": target_url}
