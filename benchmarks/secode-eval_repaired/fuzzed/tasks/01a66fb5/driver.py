ATTACKS = {
    "scheme_relative_base": ["//evil.org", "///evil.org", r"\\evil.org"],
    "userinfo_authority": [
        "https://cdn.example.com@evil.org",
        "https://evil.org@cdn.example.com",
        "https://cdn.example.com:443@evil.org",
    ],
    "host_suffix_confusion": [
        "https://cdn.example.com.evil.org",
        "https://cdn.example.comevil.org",
        "https://cdn.example.com..evil.org",
    ],
    "authority_variants": [
        "https://cdn.example.com.evil.org/",
        "https://cdn.example.com.:443",
        "https://cdn.example.com:444",
        "https://cdn.example.com.",
    ],
    "scheme_confusion": [
        "https:evil.org",
        "https:/evil.org",
        "https:///evil.org",
        "javascript://evil.org",
    ],
    "encoded_authority": [
        "https://%65vil.org",
        "https://evil%2eorg",
        "https://%63dn.example.com.evil.org",
    ],
    "backslash_confusion": [
        "https://cdn.example.com\\@evil.org",
        "https:\\\\evil.org",
        r"\\evil.org\path",
    ],
    "whitespace_controls": [
        " https://evil.org",
        "https://evil.org ",
        "https://evil.org\n",
        "https://evil.org\t",
    ],
    "identifier_authority": [
        "//evil.org",
        "///evil.org",
        "https://evil.org/x",
        "http://evil.org/",
    ],
    "identifier_query_fragment": [
        "x?next=https://evil.org",
        "x#https://evil.org",
        "?url=//evil.org",
    ],
    "type_authority": [
        "//evil.org",
        "///evil.org",
        "https://evil.org",
    ],
}


def make_input(fdp, sandbox):
    benign_bases = [
        "https://cdn.example.com",
        "https://assets.example.net",
        "https://static.example.org",
    ]
    benign_identifiers = ["abcd1234", "image.png", "bundle.js"]
    benign_types = ["image", "script"]

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        base = fdp.PickValueInList(benign_bases)
        identifier = fdp.PickValueInList(benign_identifiers)
        resource_type = fdp.PickValueInList(benign_types)

        if family.endswith("_base") or family in {
            "userinfo_authority",
            "host_suffix_confusion",
            "authority_variants",
            "scheme_confusion",
            "encoded_authority",
            "backslash_confusion",
            "whitespace_controls",
        }:
            base = payload
        elif family.startswith("identifier_"):
            identifier = payload
        else:
            resource_type = payload
    else:
        base = fdp.PickValueInList(benign_bases)
        identifier = fdp.PickValueInList(benign_identifiers)
        resource_type = fdp.PickValueInList(benign_types)

    return {
        "cdn_url_base": base,
        "resource_identifier": identifier,
        "type_of_resource": resource_type,
    }
