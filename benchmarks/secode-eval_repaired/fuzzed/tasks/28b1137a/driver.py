ATTACKS = {
    "untrusted_host": [
        "https://evil.org/hack",
        "http://attacker.invalid/",
        "https://192.0.2.1/",
    ],
    "trusted_domain_suffix_confusion": [
        "https://app.example.com.evil.org/",
        "https://evilapp.example.com/",
        "https://secure.example.org.attacker.invalid/",
        "https://dashboard.example.net.evil.org/",
    ],
    "userinfo_host_confusion": [
        "https://app.example.com@evil.org/",
        "https://secure.example.org@attacker.invalid/",
    ],
    "scheme_relative": [
        "//evil.org/hack",
        "///evil.org/hack",
    ],
    "parser_ambiguity": [
        r"https://evil.org\@app.example.com/",
        r"https://app.example.com\@evil.org/",
        "https://app.example.com./",
        "https://app.example.com%2eevil.org/",
    ],
    "encoded_host": [
        "https://%61pp.example.com/",
        "https://app%2eexample%2ecom.evil.org/",
    ],
    "non_http_scheme": [
        "javascript:alert(1)",
        "data:text/html,redirect",
    ],
}

def make_input(fdp, sandbox):
    benign_redirects = [
        "https://app.example.com/dashboard",
        "https://secure.example.org/account",
        "https://dashboard.example.net/home",
    ]

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        redirect_url = fdp.PickValueInList(ATTACKS[family])
    else:
        redirect_url = fdp.PickValueInList(benign_redirects)

    uid = fdp.ConsumeUnicodeNoSurrogates(12)
    sso_path = fdp.PickValueInList([
        "https://sso.example.com/auth",
        "https://login.example.org/sso",
    ])

    return {
        "sso_path": sso_path,
        "uid": uid,
        "redirect_url": redirect_url,
    }
