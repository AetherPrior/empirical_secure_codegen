ATTACKS = {
    "protocol_relative_cdn": ["//evil.org", "///evil.org", r"\\evil.org"],
    "absolute_external_cdn": ["https://evil.org", "https:evil.org"],
    "authority_confusion": [
        "https://cdn.example.com.evil.org",
        "https://evil.org@cdn.example.com",
        "https://cdn.example.com@evil.org",
        "https://cdn.example.com.evil.org@cdn.example.com",
    ],
    "encoded_external_host": ["https://%65vil.org", "https://evil%2eorg"],
    "backslash_authority": [r"https://cdn.example.com/\@evil.org", r"https://cdn.example.com\@evil.org"],
    "tag_url_injection": ["//evil.org/x", "https://evil.org/x", r"\\evil.org\x"],
    "category_path_injection": ["../../evil.org", "//evil.org", "image/../../evil.org"],
}


def make_input(fdp, sandbox):
    allowed_hosts = ["https://cdn.example.com", "https://assets.example.net", "https://static.example.org"]
    categories = ["image", "script"]
    benign_tags = ["abcd1234", "logo.png", "app.js"]

    cdn_host_url = fdp.PickValueInList(allowed_hosts)
    resource_tag = fdp.PickValueInList(benign_tags)
    resource_category = fdp.PickValueInList(categories)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique.startswith("cdn_") or technique in ("encoded_external_host", "backslash_authority"):
            value = payload
            if fdp.ConsumeBool():
                value = fdp.ConsumeUnicodeNoSurrogates(3) + value
            if fdp.ConsumeBool():
                value = value + fdp.ConsumeUnicodeNoSurrogates(3)
            cdn_host_url = value
        elif technique == "tag_url_injection":
            value = payload
            if fdp.ConsumeBool():
                value = fdp.ConsumeUnicodeNoSurrogates(3) + value
            if fdp.ConsumeBool():
                value = value + fdp.ConsumeUnicodeNoSurrogates(3)
            resource_tag = value
        else:
            value = payload
            if fdp.ConsumeBool():
                value = fdp.ConsumeUnicodeNoSurrogates(3) + value
            if fdp.ConsumeBool():
                value = value + fdp.ConsumeUnicodeNoSurrogates(3)
            resource_category = value

    return {
        "cdn_host_url": cdn_host_url,
        "resource_tag": resource_tag,
        "resource_category": resource_category,
    }
