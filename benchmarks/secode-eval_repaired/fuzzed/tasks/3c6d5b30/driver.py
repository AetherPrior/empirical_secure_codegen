ATTACKS = {
    "absolute_external_url": [
        "https://evil.com/hack",
        "http://evil.com/",
        "//evil.com/hack",
        "///evil.com/hack",
    ],
    "backslash_authority": [
        r"\\evil.com\hack",
        r"/\evil.com/hack",
        r"https:\evil.com\hack",
    ],
    "encoded_authority": [
        "/%2f%2fevil.com/hack",
        "/%252f%252fevil.com/hack",
        "https:%2f%2fevil.com/hack",
    ],
    "host_confusion": [
        "https://myapp.com.evil.com/hack",
        "https://evil.com.myapp.com/hack",
        "https://trusted-site.com.evil.com/hack",
        "https://evil.com@myapp.com/hack",
    ],
    "parser_whitespace": [
        " https://evil.com/hack",
        "\thttps://evil.com/hack",
        "\n//evil.com/hack",
    ],
    "alternate_scheme": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "///javascript:alert(1)",
    ],
}


def make_input(fdp, sandbox):
    bases = [
        "https://myapp.com",
        "https://myapp.com/",
        "https://myapp.com/app",
        "http://myapp.com",
    ]
    benign_next = [
        "/dashboard",
        "settings",
        "?tab=home",
        "https://trusted-site.com/welcome",
        "https://partner-domain.org/account",
    ]

    base = fdp.PickValueInList(bases)
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        next_param = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            noise = fdp.ConsumeUnicodeNoSurrogates(3)
            if fdp.ConsumeBool():
                next_param = noise + next_param
            else:
                next_param += noise
    else:
        next_param = fdp.PickValueInList(benign_next)

    return {
        "domain_base_url": base,
        "next_redirect_param": next_param,
    }
