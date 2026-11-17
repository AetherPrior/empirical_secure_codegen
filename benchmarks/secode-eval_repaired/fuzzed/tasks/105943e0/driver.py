ATTACKS = {
    "external_absolute_url": [
        "https://evil.org/hack",
        "http://evil.org/",
    ],
    "scheme_relative_url": [
        "//evil.org/hack",
        "///evil.org/hack",
    ],
    "allowed_domain_suffix_confusion": [
        "https://app.example.com.evil.org/",
        "https://evilapp.example.com/",
        "https://app.example.com@evil.org/",
    ],
    "userinfo_authority_confusion": [
        "https://evil.org@app.example.com/",
        "https://evil.org%2f@app.example.com/",
    ],
    "subdomain_and_trailing_dot": [
        "https://evil.app.example.com/",
        "https://app.example.com./",
    ],
    "backslash_authority_confusion": [
        r"https://evil.org\@app.example.com/",
        r"https://app.example.com\@evil.org/",
    ],
    "non_http_scheme": [
        "javascript:alert(1)",
        "data:text/html,redirect",
    ],
    "encoded_authority": [
        "https://%65vil.org/",
        "https://evil%2eorg/",
    ],
}


def make_input(fdp, sandbox):
    allowed_domains = [
        "app.example.com",
        "secure.example.org",
        "dashboard.example.net",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        callback_url = fdp.PickValueInList(ATTACKS[technique])
    else:
        domain = fdp.PickValueInList(allowed_domains)
        path = fdp.PickValueInList(["/", "/dashboard", "/account", "/sso/complete"])
        callback_url = "https://" + domain + path

    account_id = fdp.PickValueInList(["user101", "user123", "account-7"])
    return {
        "login_endpoint": "https://sso.example.com/auth",
        "account_id": account_id,
        "callback_url": callback_url,
    }
