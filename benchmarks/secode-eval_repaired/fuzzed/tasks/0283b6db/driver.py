ATTACKS = {
    "external_absolute": [
        "https://evil.org/hack",
        "http://attacker.invalid/redirect",
    ],
    "protocol_relative": [
        "//evil.org/hack",
        "///evil.org/hack",
    ],
    "domain_suffix_confusion": [
        "https://app.example.com.evil.org/",
        "https://secure.example.org.attacker.invalid/",
        "https://evil.org/app.example.com",
    ],
    "subdomain_confusion": [
        "https://evil.app.example.com/",
        "https://attacker.secure.example.org/",
    ],
    "userinfo_confusion": [
        "https://app.example.com@evil.org/",
        "https://secure.example.org@attacker.invalid/",
    ],
    "parser_and_encoding_confusion": [
        r"https:\\evil.org\hack",
        r"\\evil.org\hack",
        "https://%65vil.org/",
        "%2f%2fevil.org%2fhack",
    ],
    "unsafe_scheme": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "whitelist_in_path_or_fragment": [
        "https://evil.org/?next=https://app.example.com/",
        "https://evil.org/#app.example.com",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        return_url = fdp.PickValueInList([
            "https://app.example.com/dashboard",
            "https://secure.example.org/account",
            "https://dashboard.example.net/home",
        ])
        if fdp.ConsumeBool():
            return_url += "/" + fdp.ConsumeUnicodeNoSurrogates(8)
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        return_url = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            return_url += "/" + fdp.ConsumeUnicodeNoSurrogates(8)

    return {
        "sso_endpoint": "https://sso.example.com/auth",
        "user_id": fdp.ConsumeUnicodeNoSurrogates(12),
        "return_url": return_url,
    }
