ATTACKS = {
    "untrusted_host": [
        "https://evil.org/hack",
        "https://evil.org/",
        "http://evil.org/hack",
    ],
    "allowlist_suffix": [
        "https://app.example.com.evil.org/",
        "https://secure.example.org.evil.org/",
        "https://dashboard.example.net.evil.org/",
    ],
    "userinfo_confusion": [
        "https://app.example.com@evil.org/",
        "https://secure.example.org@evil.org/",
        "https://evil.org@app.example.com/",
    ],
    "subdomain_confusion": [
        "https://evil.app.example.com/",
        "https://app.example.com.evil.org/",
    ],
    "scheme_relative": [
        "//evil.org/hack",
        "///evil.org/hack",
        "\\\\evil.org\\hack",
    ],
    "parser_normalization": [
        "https://app.example.com./",
        "https://app.example.com:443.evil.org/",
        "https://app.example.com%2eevil.org/",
        "https://app.example.com\\@evil.org/",
        " https://evil.org/hack",
        "https://evil.org/hack ",
    ],
    "non_http_scheme": [
        "javascript:alert(1)",
        "data:text/html,https://evil.org/",
    ],
    "encoded_destination": [
        "https://evil.org/%2f%2fevil.org/",
        "https://evil.org/%252f%252fevil.org/",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        redirect_back_url = fdp.PickValueInList(ATTACKS[technique])
    else:
        redirect_back_url = fdp.PickValueInList([
            "https://app.example.com/dashboard",
            "https://secure.example.org/return",
            "https://dashboard.example.net/home",
        ])

    return {
        "sso_service_url": "https://sso.example.com/auth",
        "user_identifier": fdp.PickValueInList([
            "user123",
            "user101",
            fdp.ConsumeUnicodeNoSurrogates(12),
        ]),
        "redirect_back_url": redirect_back_url,
    }
