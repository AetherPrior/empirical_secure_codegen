ATTACKS = {
    "scheme_relative": [
        "//evil.com/hack",
        "///evil.com/hack",
        "//evil.com",
    ],
    "absolute_external_url": [
        "https://evil.com/",
        "http://evil.com/hack",
        "https://evil.com:443/redirect",
    ],
    "deceptive_host": [
        "https://myapp.com.evil.com/",
        "https://evil.com.myapp.com/",
        "https://trusted-site.com.evil.com/",
    ],
    "userinfo_host_confusion": [
        "https://myapp.com@evil.com/",
        "https://trusted-site.com@evil.com/",
    ],
    "backslash_authority": [
        r"\\evil.com\hack",
        r"\/\evil.com/hack",
    ],
    "alternate_scheme": [
        "javascript:alert(1)",
        "data:text/html,redirect",
        "https:evil.com",
    ],
    "encoded_authority": [
        "%2f%2fevil.com/hack",
        "%252f%252fevil.com/hack",
    ],
    "whitespace_and_controls": [
        " //evil.com/hack",
        "\t//evil.com/hack",
        "/%0d%0aLocation:%20https://evil.com/",
    ],
}

def make_input(fdp, sandbox):
    app_url = fdp.PickValueInList([
        "https://myapp.com",
        "https://myapp.com/",
        "https://login.myapp.com",
    ])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        redirect_param = fdp.PickValueInList(ATTACKS[technique])

        # Sometimes splice small fuzz text onto the payload without changing its
        # authority or scheme.
        if fdp.ConsumeBool() and "?" not in redirect_param and "#" not in redirect_param:
            fuzz = fdp.ConsumeUnicodeNoSurrogates(6)
            suffix = "".join(char for char in fuzz if char.isalnum())
            if suffix:
                redirect_param += "?fuzz=" + suffix
    else:
        redirect_param = fdp.PickValueInList([
            "/dashboard",
            "/account/settings",
            "/orders?page=1",
            "profile",
        ])

    return {"app_url": app_url, "redirect_param": redirect_param}
