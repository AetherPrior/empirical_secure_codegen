ATTACKS = {
    "external_host": [
        "https://evil.org/hack",
        "http://attacker.invalid/return",
    ],
    "protocol_relative": [
        "//evil.org/hack",
        "///evil.org/hack",
    ],
    "userinfo": [
        "https://app.example.com@evil.org/hack",
        "https://evil.org@app.example.com/hack",
    ],
    "hostname_suffix": [
        "https://app.example.com.evil.org/hack",
        "https://secure.example.org.attacker.invalid/",
    ],
    "untrusted_subdomain": [
        "https://evil.app.example.com/hack",
        "https://attacker.secure.example.org/",
    ],
    "allowed_domain_in_path_or_query": [
        "https://evil.org/app.example.com",
        "https://evil.org/?next=https://app.example.com/",
    ],
    "backslash_authority_confusion": [
        r"https://evil.org\@app.example.com/hack",
        r"https:\evil.org\hack",
    ],
    "encoded_host": [
        "https://%61pp.example.com/hack",
        "https://evil%2eorg/hack",
    ],
    "leading_whitespace": [
        " https://evil.org/hack",
        "\t//evil.org/hack",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        redirect_uri = fdp.PickValueInList(ATTACKS[technique])
    else:
        redirect_uri = fdp.PickValueInList([
            "https://app.example.com/dashboard",
            "https://secure.example.org/account",
            "https://dashboard.example.net/home",
        ])

    user_identifier = fdp.ConsumeUnicodeNoSurrogates(12)
    if not user_identifier:
        user_identifier = "user123"

    return {
        "auth_service_endpoint": "https://sso.example.com/auth",
        "user_identifier": user_identifier,
        "redirect_uri": redirect_uri,
    }
