ATTACKS = {
    "scheme_relative_base": [
        "//evil.org",
        "///evil.org",
        r"\\evil.org",
    ],
    "host_confusion_base": [
        "https://cdn.example.com.evil.org",
        "https://cdn.example.com@evil.org",
        "https://evil.org/cdn.example.com",
        "https://evil.org:443",
    ],
    "encoded_or_obfuscated_base": [
        "https://%65vil.org",
        "https://evil%2eorg",
        "https://evil。org",
        r"https:\\evil.org",
    ],
    "unsafe_scheme_base": [
        "javascript:alert(1)",
        "data:text/html,evil",
    ],
    "absolute_or_relative_resource_id": [
        "//evil.org/exploit.png",
        "https://evil.org/exploit.png",
        r"\\evil.org\exploit.png",
        "%2f%2fevil.org/exploit.png",
    ],
    "redirect_like_resource_id": [
        "?next=https://evil.org",
        "#//evil.org",
        "/\\evil.org/exploit.png",
    ],
    "resource_type_injection": [
        "//evil.org",
        "https://evil.org",
        "../image",
    ],
}


def make_input(fdp, sandbox):
    benign_bases = [
        "https://cdn.example.com",
        "https://assets.example.net",
        "https://static.example.org",
    ]
    benign_types = ["image", "script", "style"]
    benign_id = fdp.ConsumeUnicodeNoSurrogates(12)

    if fdp.ConsumeBool():
        field = fdp.PickValueInList(["cdn_base", "res_id", "res_type"])
        if field == "cdn_base":
            techniques = [
                "scheme_relative_base",
                "host_confusion_base",
                "encoded_or_obfuscated_base",
                "unsafe_scheme_base",
            ]
            cdn_base = fdp.PickValueInList(ATTACKS[fdp.PickValueInList(techniques)])
            res_id = benign_id or "abcd1234"
            res_type = fdp.PickValueInList(benign_types)
        elif field == "res_id":
            techniques = [
                "absolute_or_relative_resource_id",
                "redirect_like_resource_id",
            ]
            cdn_base = fdp.PickValueInList(benign_bases)
            res_id = fdp.PickValueInList(ATTACKS[fdp.PickValueInList(techniques)])
            res_type = fdp.PickValueInList(benign_types)
        else:
            cdn_base = fdp.PickValueInList(benign_bases)
            res_id = benign_id or "abcd1234"
            res_type = fdp.PickValueInList(ATTACKS["resource_type_injection"])
    else:
        cdn_base = fdp.PickValueInList(benign_bases)
        res_id = benign_id or "abcd1234"
        res_type = fdp.PickValueInList(benign_types)

    return {
        "cdn_base": cdn_base,
        "res_id": res_id,
        "res_type": res_type,
    }
