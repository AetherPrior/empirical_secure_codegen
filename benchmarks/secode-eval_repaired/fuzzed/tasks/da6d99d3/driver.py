ATTACKS = {
    "scheme_relative": ["//evil.org", "///evil.org", "////evil.org"],
    "absolute_external": ["http://evil.org/x", "https://evil.org/x"],
    "userinfo_confusion": [
        "https://cdn.example.com@evil.org/x",
        "https://evil.org@cdn.example.com/x",
    ],
    "host_suffix": [
        "https://cdn.example.com.evil.org/x",
        "https://evil.org/cdn.example.com",
    ],
    "scheme_confusion": ["https:////evil.org/x", "javascript://evil.org/x"],
    "backslash_authority": [r"\\evil.org\x", r"https:\\evil.org\x"],
    "encoded_authority": ["%2f%2fevil.org/x", "%5c%5cevil.org/x"],
    "resource_key_authority": ["//evil.org/x", "///evil.org/x"],
    "resource_key_absolute": ["https://evil.org/x", "http://evil.org/x"],
    "resource_key_encoded": ["%2f%2fevil.org/x", "%5c%5cevil.org/x"],
}


def make_input(fdp, sandbox):
    cdn_values = [
        "https://cdn.example.com",
        "https://assets.example.net",
        "https://static.example.org",
    ]
    resource_values = ["abcd1234", "images/logo.png", "scripts/app.js"]
    category_values = ["image", "script", "resource"]

    cdn_url = fdp.PickValueInList(cdn_values)
    resource_key = fdp.PickValueInList(resource_values)
    res_category = fdp.PickValueInList(category_values)

    if fdp.ConsumeBool():
        target = fdp.PickValueInList(["cdn_url", "resource_key"])
        if target == "cdn_url":
            techniques = [
                "scheme_relative",
                "absolute_external",
                "userinfo_confusion",
                "host_suffix",
                "scheme_confusion",
                "backslash_authority",
                "encoded_authority",
            ]
        else:
            techniques = [
                "resource_key_authority",
                "resource_key_absolute",
                "resource_key_encoded",
            ]

        technique = fdp.PickValueInList(techniques)
        payload = fdp.PickValueInList(ATTACKS[technique])

        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            if fdp.ConsumeBool():
                payload = fuzz + payload
            else:
                payload = payload + fuzz

        if target == "cdn_url":
            cdn_url = payload
        else:
            resource_key = payload

    return {
        "cdn_url": cdn_url,
        "resource_key": resource_key,
        "res_category": res_category,
    }
