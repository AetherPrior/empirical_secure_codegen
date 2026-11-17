ATTACKS = {
    "absolute_external": [
        "https://evil.com/hack",
        "http://evil.com/",
        "https://evil.com",
    ],
    "protocol_relative": [
        "//evil.com/hack",
        "///evil.com/hack",
        "////evil.com/hack",
    ],
    "backslash_slashes": [
        r"\\evil.com\hack",
        r"/\evil.com/hack",
    ],
    "host_confusion": [
        "https://myapp.com.evil.com/",
        "https://evil.com/myapp.com",
        "https://myapp.com@evil.com/",
        "//trusted-site.com.evil.com/",
    ],
    "encoded_slashes": [
        "%2f%2fevil.com/hack",
        "/%2f%2fevil.com/hack",
        "%252f%252fevil.com/hack",
    ],
    "dangerous_schemes": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "whitespace_prefix": [
        " https://evil.com/hack",
        "\thttps://evil.com/hack",
        "\n//evil.com/hack",
    ],
}

def make_input(fdp, sandbox):
    app_home_url = fdp.PickValueInList([
        "https://myapp.com",
        "https://myapp.com/",
    ])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        forward_param = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            fuzz = "".join(ch for ch in fuzz if ch.isalnum())[:4]
            forward_param += "?f=" + fuzz
    else:
        forward_param = fdp.PickValueInList([
            "/dashboard",
            "/account/profile",
            "settings",
            "/search?q=hello",
            "https://myapp.com/help",
            "https://trusted-site.com/welcome",
            "https://partner-domain.org/continue",
        ])

    return {
        "app_home_url": app_home_url,
        "forward_param": forward_param,
    }
