ATTACKS = {
    "authority_override": [
        "//evil.org",
        "https://evil.org",
        "https://cdn.example.com@evil.org",
        "https://evil.org@cdn.example.com",
        "https://cdn.example.com.evil.org",
        "https://evil.org/cdn.example.com",
    ],
    "authority_confusion": [
        "https://cdn.example.com%2eevil.org",
        "https://cdn.example.com\\@evil.org",
        "http://cdn.example.com:80@evil.org",
        "https://cdn.example.com./",
    ],
    "resource_url_override": [
        "//evil.org/x",
        "\\\\evil.org\\x",
        "https://evil.org/x",
        "///evil.org/x",
        "%2f%2fevil.org/x",
        "../..//evil.org",
        "javascript:alert(1)",
        "?url=//evil.org",
    ],
    "type_path_override": [
        "//evil.org",
        "https:",
        "image/../../",
        "..",
        "script//evil.org",
    ],
}


def make_input(fdp, sandbox):
    benign_bases = [
        "https://cdn.example.com",
        "https://assets.example.net/",
        "https://static.example.org/resources",
    ]
    benign_ids = ["abcd1234", "photo.png", "bundle.min.js"]
    benign_types = ["image", "script", "style"]

    def attack_value(family):
        value = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            if suffix:
                value += "/" + suffix
        return value

    base = fdp.PickValueInList(benign_bases)
    res_id = fdp.PickValueInList(benign_ids)
    res_type = fdp.PickValueInList(benign_types)

    if fdp.ConsumeBool():
        target = fdp.ConsumeIntInRange(0, 2)
        if target == 0:
            family = fdp.PickValueInList(
                ["authority_override", "authority_confusion"]
            )
            base = attack_value(family)
        elif target == 1:
            res_id = attack_value("resource_url_override")
        else:
            res_type = attack_value("type_path_override")

        if fdp.ConsumeBool():
            res_id = attack_value("resource_url_override")
    else:
        if fdp.ConsumeBool():
            res_id = fdp.ConsumeUnicodeNoSurrogates(12)
        if fdp.ConsumeBool():
            res_type = fdp.PickValueInList(benign_types)

    return {
        "base_cdn_url": base,
        "res_id": res_id,
        "res_type": res_type,
    }
