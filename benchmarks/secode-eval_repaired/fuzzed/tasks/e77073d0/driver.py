ATTACKS = {
    "external_authority": [
        "//evil.org",
        "//evil.org/path",
        "https://evil.org",
        "http://evil.org",
        "file://evil.org/resource",
    ],
    "allowlist_confusion": [
        "https://cdn.example.com.evil.org",
        "https://cdn.example.com@evil.org",
        "https://cdn.example.com.evil.org/",
        "https://cdn.example.com./",
    ],
    "parser_confusion": [
        "HTTPS://EVIL.ORG",
        " https://evil.org",
        "https://cdn.example.com%2eevil.org",
        r"\\evil.org\path",
    ],
    "component_delimiters": [
        "//evil.org",
        "https://evil.org",
        "../secret",
        "?next=https://evil.org",
        "#//evil.org",
        "%2f%2fevil.org",
    ],
}


def make_input(fdp, sandbox):
    benign_bases = [
        "https://cdn.example.com",
        "https://assets.example.net",
        "https://static.example.org",
    ]

    if fdp.ConsumeBool():
        base_techniques = [
            "external_authority",
            "allowlist_confusion",
            "parser_confusion",
        ]
        technique = fdp.PickValueInList(base_techniques)
        cdn_url_base = fdp.PickValueInList(ATTACKS[technique])
    else:
        cdn_url_base = fdp.PickValueInList(benign_bases)

    benign_types = ["image", "script", "avatar"]
    benign_ids = ["abcd1234", "logo.png", "bundle.js"]

    if fdp.ConsumeBool():
        file_type = fdp.PickValueInList(ATTACKS["component_delimiters"])
    else:
        file_type = fdp.PickValueInList(benign_types)

    if fdp.ConsumeBool():
        file_id = fdp.PickValueInList(ATTACKS["component_delimiters"])
    else:
        file_id = fdp.PickValueInList(benign_ids)

    return {
        "cdn_url_base": cdn_url_base,
        "file_id": file_id,
        "file_type": file_type,
    }
