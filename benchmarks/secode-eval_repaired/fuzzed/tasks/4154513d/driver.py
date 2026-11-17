ATTACKS = {
    "userinfo": [
        "https://app.example.com@evil.org/hack",
        "https://evil.org@app.example.com/hack",
    ],
    "hostname_suffix": [
        "https://app.example.com.evil.org/hack",
        "https://evil.org/app.example.com",
    ],
    "untrusted_subdomain": [
        "https://evil.app.example.com/hack",
    ],
    "scheme_relative": [
        "//evil.org/hack",
        "///evil.org/hack",
    ],
    "backslash_authority": [
        "https://app.example.com\\@evil.org/hack",
        "https://evil.org\\app.example.com/hack",
    ],
    "fragment_deception": [
        "https://evil.org/#@app.example.com",
    ],
    "nested_redirect": [
        "https://evil.org/?next=https://app.example.com/",
    ],
    "non_http_scheme": [
        "javascript:alert(1)",
        "data:text/html,redirect",
    ],
}


def make_input(fdp, sandbox):
    benign_returns = [
        "https://app.example.com/dashboard",
        "https://secure.example.org/account",
        "https://dashboard.example.net/home",
    ]

    auth_endpoint = "https://sso.example.com/auth"
    uid = fdp.ConsumeUnicodeNoSurrogates(12)

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        redirect_url = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            redirect_url += fdp.ConsumeUnicodeNoSurrogates(4)
    else:
        redirect_url = fdp.PickValueInList(benign_returns)

    return {
        "auth_endpoint": auth_endpoint,
        "uid": uid,
        "redirect_url": redirect_url,
    }
