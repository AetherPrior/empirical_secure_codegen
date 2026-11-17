ATTACKS = {
    "external_host": [
        "https://evil.org/hack",
        "http://attacker.invalid/",
        "https://evil.org:443/path",
    ],
    "scheme_relative": [
        "//evil.org/hack",
        "///evil.org/hack",
        "//app.example.com.evil.org/",
    ],
    "host_confusion": [
        "https://app.example.com.evil.org/",
        "https://evilapp.example.com/",
        "https://app.example.com@evil.org/",
        "https://app.example.com%2eevil.org/",
    ],
    "parser_normalization": [
        r"https://evil.org\@app.example.com/",
        r"https://app.example.com\@evil.org/",
        " https://evil.org/hack",
        "\thttps://evil.org/hack",
        "https://evil.org%2f.example.com/",
    ],
    "unsafe_scheme": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
    ],
}


def make_input(fdp, sandbox):
    benign_redirects = [
        "https://app.example.com/dashboard",
        "https://secure.example.org/account",
        "https://dashboard.example.net/home",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        redirect_url = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
            separator = "&" if "?" in redirect_url else "?"
            redirect_url += separator + "probe=" + urllib.parse.quote(fuzz, safe="")
    else:
        redirect_url = fdp.PickValueInList(benign_redirects)

    return {
        "sso_url": "https://sso.example.com/auth",
        "uid": fdp.PickValueInList(["user123", "user101", "member7"]),
        "redirect_url": redirect_url,
    }
