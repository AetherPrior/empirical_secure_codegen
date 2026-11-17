ATTACKS = {
    "absolute_external": [
        "https://anotherbad.com/malware",
        "http://evil.example/path",
    ],
    "scheme_relative": [
        "//anotherbad.com/malware",
        "//evil.example/path",
    ],
    "slash_confusion": [
        "///evil.example/path",
        "////evil.example/path",
        "/\\evil.example/path",
        "\\\\evil.example/path",
    ],
    "allowed_domain_suffix": [
        "https://trusted-site.com.evil.example/path",
        "//partner-domain.org.evil.example/path",
    ],
    "userinfo_confusion": [
        "https://trusted-site.com@evil.example/path",
        "//application.com@evil.example/path",
    ],
    "encoded_authority": [
        "/%2f%2fevil.example/path",
        "/%5c%5cevil.example/path",
        "https:%2f%2fevil.example/path",
    ],
    "whitespace_obfuscation": [
        " https://evil.example/path",
        "\thttps://evil.example/path",
        "https://evil.example\t/path",
    ],
}

def make_input(fdp, sandbox):
    main_base_url = fdp.PickValueInList([
        "https://application.com",
        "https://application.com/login",
    ])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        next_route = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            next_route += "?probe=" + fdp.ConsumeUnicodeNoSurrogates(6)
    else:
        next_route = fdp.PickValueInList([
            "/profile",
            "/settings",
            "https://trusted-site.com/account",
            "https://partner-domain.org/continue",
        ])

    return {
        "main_base_url": main_base_url,
        "next_route": next_route,
    }
