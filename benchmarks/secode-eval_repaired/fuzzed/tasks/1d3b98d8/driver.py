ATTACKS = {
    "scheme_relative_authority": [
        "//evil.org",
        "///evil.org",
        "////evil.org",
        "//evil.org/path",
    ],
    "absolute_external_url": [
        "https://evil.org",
        "http://evil.org/resource",
        "javascript://evil.org",
    ],
    "userinfo_authority_confusion": [
        "https://cdn.example.com@evil.org",
        "https://evil.org@cdn.example.com",
        "//cdn.example.com@evil.org",
        "//evil.org\\@cdn.example.com",
    ],
    "hostname_suffix_confusion": [
        "https://cdn.example.com.evil.org",
        "https://evilcdn.example.com",
        "https://cdn.example.com.evil.org/",
        "//assets.example.net.evil.org",
    ],
    "parser_normalization": [
        "https://cdn.example.com./",
        "//%63dn.example.com",
        "//cdn.example.com%2eevil.org",
        "https://cdn.example.com\\@evil.org",
    ],
    "identifier_external_reference": [
        "//evil.org/x",
        "https://evil.org/x",
        "\\\\evil.org\\x",
        "/\\\\evil.org/x",
    ],
    "identifier_delimiter_injection": [
        "?url=https://evil.org",
        "#//evil.org",
        "/x?next=//evil.org",
        "/x#https://evil.org",
    ],
    "identifier_encoded_reference": [
        "%2f%2fevil.org",
        "%5c%5cevil.org",
        "%252f%252fevil.org",
        "%3a%2f%2fevil.org",
    ],
    "kind_url_injection": [
        "//evil.org",
        "https://evil.org",
        "image/../..///evil.org",
    ],
}


def make_input(fdp, sandbox):
    cdn_url = "https://cdn.example.com"
    resource_identifier = "abcd1234"
    resource_kind = fdp.PickValueInList(["image", "script"])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        target = fdp.ConsumeIntInRange(0, 2)

        if target == 0:
            cdn_url = payload
        elif target == 1:
            resource_identifier = payload
        else:
            resource_kind = payload

        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            if target == 0:
                cdn_url = payload + fuzz
            elif target == 1:
                resource_identifier = fuzz + payload
            else:
                resource_kind = payload + fuzz
    else:
        resource_identifier = fdp.ConsumeUnicodeNoSurrogates(12)

    return {
        "cdn_url": cdn_url,
        "resource_identifier": resource_identifier,
        "resource_kind": resource_kind,
    }
