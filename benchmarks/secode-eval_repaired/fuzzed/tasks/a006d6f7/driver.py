ATTACKS = {
    "scheme_relative_origin": [
        "//evil.org",
        "///evil.org",
        r"\\evil.org",
    ],
    "external_origin": [
        "https://evil.org",
        "http://evil.org/path",
    ],
    "userinfo_origin": [
        "https://cdn.example.com@evil.org",
        "https://evil.org@cdn.example.com",
    ],
    "host_suffix_confusion": [
        "https://cdn.example.com.evil.org",
        "https://cdn.example.com.evil.org/",
        "https://cdn.example.com%2eevil.org",
    ],
    "host_normalization": [
        "https://cdn.example.com.",
        "https://CDN.EXAMPLE.COM",
        "https://cdn。example.com",
    ],
    "path_injection_id": [
        "//evil.org",
        "/../../evil.org/resource",
        r"\\evil.org\resource",
        "https://evil.org/resource",
    ],
    "path_injection_kind": [
        "//evil.org",
        "/../../evil.org",
        r"\\evil.org",
        "https://evil.org",
    ],
    "url_delimiters": [
        "evil.org@cdn.example.com",
        "x?next=https://evil.org",
        "x#//evil.org",
    ],
}


def make_input(fdp, sandbox):
    benign_origins = [
        "https://cdn.example.com",
        "https://assets.example.net",
        "https://static.example.org",
    ]
    benign_ids = ["abcd1234", "exploit.png", "asset-7"]
    benign_kinds = ["image", "script", "video"]

    origin = fdp.PickValueInList(benign_origins)
    content_id = fdp.PickValueInList(benign_ids)
    content_kind = fdp.PickValueInList(benign_kinds)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique in {
            "scheme_relative_origin",
            "external_origin",
            "userinfo_origin",
            "host_suffix_confusion",
            "host_normalization",
        }:
            origin = payload
        elif technique == "path_injection_id":
            content_id = payload
        elif technique == "path_injection_kind":
            content_kind = payload
        else:
            content_id = payload

    return {
        "cdn_origin_url": origin,
        "content_id": content_id,
        "content_kind": content_kind,
    }
