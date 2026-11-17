import urllib.parse

ALLOWED_RETURN_DOMAINS = {
    "app.example.com",
    "secure.example.org",
    "dashboard.example.net",
}

ATTACKS = {
    "trusted_domain_suffix": [
        "https://app.example.com.evil.org/hack",
        "https://secure.example.org.attacker.net/",
    ],
    "userinfo_confusion": [
        "https://app.example.com@evil.org/hack",
        "https://secure.example.org@attacker.net/",
    ],
    "trusted_domain_in_path_or_query": [
        "https://evil.org/app.example.com",
        "https://evil.org/?next=https://app.example.com/",
    ],
    "protocol_relative": [
        "//evil.org/hack",
        "///evil.org/hack",
    ],
    "unsafe_scheme": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "authority_parser_confusion": [
        r"https://evil.org\@app.example.com/",
        "https://app.example.com%2eevil.org/",
        "https://evil.org#@app.example.com/",
    ],
    "whitespace_and_control": [
        " https://evil.org/hack",
        "https://evil.org/hack\n",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        redirect_url = fdp.PickValueInList(ATTACKS[technique])
    else:
        redirect_url = fdp.PickValueInList([
            "https://app.example.com/dashboard",
            "https://secure.example.org/account",
            "https://dashboard.example.net/home?tab=profile",
        ])

    auth_endpoint = fdp.PickValueInList([
        "https://sso.example.com/auth",
        "https://login.example.org/sso",
    ])
    uid = fdp.ConsumeUnicodeNoSurrogates(16)

    return {
        "auth_endpoint": auth_endpoint,
        "uid": uid,
        "redirect_url": redirect_url,
    }
