ATTACKS = {
    "external_absolute_url": [
        "https://evil.org/hack",
        "http://evil.org/",
        "https://evil.org:443/return",
    ],
    "protocol_relative": [
        "//evil.org/hack",
        "///evil.org/hack",
        "//evil.org\\@app.example.com/",
    ],
    "hostname_suffix_or_prefix": [
        "https://app.example.com.evil.org/",
        "https://evilapp.example.com/",
        "https://app.example.comevil.org/",
    ],
    "userinfo_confusion": [
        "https://app.example.com@evil.org/",
        "https://evil.org@app.example.com.evil.org/",
    ],
    "parser_disagreement": [
        "https://app.example.com\\@evil.org/",
        "https://evil.org\\app.example.com/",
        "https://app.example.com%2eevil.org/",
        "https://app.example.com%40evil.org/",
    ],
    "misleading_path_or_fragment": [
        "https://evil.org/app.example.com/",
        "https://evil.org/#https://app.example.com/",
        "https://evil.org/?next=https://app.example.com/",
    ],
    "non_http_scheme": [
        "javascript:alert(1)",
        "data:text/html,https://evil.org/",
    ],
    "alternate_host_representation": [
        "https://127.0.0.1/",
        "https://0x7f000001/",
        "https://xn--e1afmkfd.example/",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        redirect_link = fdp.PickValueInList(ATTACKS[technique])
    else:
        redirect_link = fdp.PickValueInList([
            "https://app.example.com/dashboard",
            "https://secure.example.org/account",
            "https://dashboard.example.net/home",
        ])

    user_identifier = fdp.PickValueInList([
        "user123",
        "user101",
        fdp.ConsumeUnicodeNoSurrogates(12),
    ])
    sso_uri = fdp.PickValueInList([
        "https://sso.example.com/auth",
        "https://sso.example.com/login",
    ])

    return {
        "sso_uri": sso_uri,
        "user_identifier": user_identifier,
        "redirect_link": redirect_link,
    }
