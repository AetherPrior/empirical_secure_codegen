ATTACKS = {
    "external_absolute": [
        "https://evil.org/hack",
        "http://attacker.invalid/redirect",
        "https://2130706433/",
    ],
    "scheme_relative": [
        "//evil.org/hack",
        "///evil.org/hack",
    ],
    "userinfo_confusion": [
        "https://app.example.com@evil.org/hack",
        "https://secure.example.org.evil.org@evil.org/",
    ],
    "suffix_host": [
        "https://app.example.com.evil.org/",
        "https://dashboard.example.net.attacker.invalid/",
    ],
    "unapproved_subdomain": [
        "https://evil.app.example.com/",
        "https://attacker.secure.example.org/",
    ],
    "backslash_authority": [
        r"https:\evil.org\hack",
        r"\\evil.org\hack",
        r"https://evil.org\@app.example.com/",
    ],
    "encoded_or_unicode_host": [
        "https://evil%2eorg/hack",
        "https://%65vil.org/hack",
        "https://evil。org/hack",
    ],
    "non_http_scheme": [
        "javascript:alert(1)",
        "data:text/html,redirect",
    ],
}


def make_input(fdp, sandbox):
    import urllib.parse

    user_ref = fdp.ConsumeUnicodeNoSurrogates(12)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        back_url = fdp.PickValueInList(ATTACKS[technique])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        if fuzz:
            back_url += "?probe=" + urllib.parse.quote(fuzz, safe="")
    else:
        back_url = fdp.PickValueInList([
            "https://app.example.com/dashboard",
            "https://secure.example.org/account",
            "https://dashboard.example.net/home",
        ])

    return {
        "sso_service": "https://sso.example.com/auth",
        "user_ref": user_ref,
        "back_url": back_url,
    }
