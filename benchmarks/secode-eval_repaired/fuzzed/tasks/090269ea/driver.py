ATTACKS = {
    "scheme_relative": [
        "//evil.org",
        "//attacker.example/cdn.example.com",
    ],
    "absolute_external": [
        "https://evil.org",
        "http://evil.org/resources",
        "HTTPS://EVIL.ORG",
    ],
    "userinfo_confusion": [
        "https://cdn.example.com@evil.org",
        "https://evil.org@cdn.example.com",
    ],
    "host_suffix": [
        "https://cdn.example.com.evil.org",
        "//cdn.example.com.evil.org/path",
    ],
    "parser_ambiguity": [
        r"https://cdn.example.com\@evil.org",
        " https://evil.org",
        "https://evil.org#@cdn.example.com",
    ],
    "resource_delimiters": [
        "?next=https://evil.org",
        "#//evil.org",
        "//evil.org/resource",
    ],
    "resource_path_traversal": [
        "../..",
        "%2e%2e%2f%2e%2e",
    ],
}


def make_input(fdp, sandbox):
    attack_families = sorted(ATTACKS)
    cdn_families = [
        "scheme_relative",
        "absolute_external",
        "userinfo_confusion",
        "host_suffix",
        "parser_ambiguity",
    ]
    resource_families = [
        "resource_delimiters",
        "resource_path_traversal",
    ]

    if fdp.ConsumeBool():
        cdn_url = fdp.PickValueInList([
            "https://cdn.example.com",
            "https://assets.example.net",
            "https://static.example.org",
        ])
    else:
        family = fdp.PickValueInList(cdn_families)
        cdn_url = fdp.PickValueInList(ATTACKS[family])

    res_id = fdp.PickValueInList(["abcd1234", "image.png", "bundle.js"])
    res_type = fdp.PickValueInList(["image", "script"])

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(resource_families)
        payload = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            res_id = payload
        else:
            res_type = payload

    return {
        "cdn_url": cdn_url,
        "res_id": res_id,
        "res_type": res_type,
    }
