ATTACKS = {
    "scheme_relative_authority": [
        "//evil.org/exploit.png",
        "///evil.org/exploit.png",
        "//evil.org",
    ],
    "absolute_external_url": [
        "https://evil.org/exploit.png",
        "http://evil.org/x",
        "javascript://evil.org/%0a",
    ],
    "host_confusion": [
        "https://cdn.example.com.evil.org/x",
        "https://cdn-example.com/x",
        "https://evil.org@cdn.example.com/x",
        "https://cdn.example.com@evil.org/x",
    ],
    "backslash_authority": [
        r"\\evil.org\exploit.png",
        r"/\evil.org/exploit.png",
        r"https:\evil.org\exploit.png",
    ],
    "encoded_authority": [
        "%2f%2fevil.org/exploit.png",
        "/%2f%2fevil.org/exploit.png",
        "%5c%5cevil.org/exploit.png",
    ],
    "base_url_external": [
        "//evil.org",
        "https://evil.org",
        "https://cdn.example.com.evil.org",
        "https://cdn.example.com@evil.org",
        r"https:\evil.org",
    ],
    "resource_type_delimiters": [
        "//evil.org",
        "https://evil.org/x",
        "../x",
    ],
}


def make_input(fdp, sandbox):
    benign_bases = [
        "https://cdn.example.com",
        "https://assets.example.net",
        "https://static.example.org",
    ]
    benign_ids = ["abcd1234", "image.png", "scripts/app.js", "icons/logo.svg"]
    benign_types = ["image", "script", "asset"]

    cdn_base_url = fdp.PickValueInList(benign_bases)
    resource_id = fdp.PickValueInList(benign_ids)
    resource_type = fdp.PickValueInList(benign_types)

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])

        if family == "base_url_external":
            cdn_base_url = payload
        elif family == "resource_type_delimiters":
            resource_type = payload
        else:
            resource_id = payload

        # Occasionally add short fuzz text without obscuring the selected payload.
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(3)
            if fdp.ConsumeBool():
                resource_id = fuzz + resource_id
            else:
                resource_id = resource_id + fuzz

    return {
        "cdn_base_url": cdn_base_url,
        "resource_id": resource_id,
        "resource_type": resource_type,
    }
