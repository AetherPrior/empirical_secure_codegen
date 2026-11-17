ATTACKS = {
    "domain_suffix_confusion": [
        "http://cdn.trusted.com.evil.invalid/image.png",
        "http://images.hosting.com.attacker.invalid/image.png",
    ],
    "domain_prefix_confusion": [
        "http://evil-cdn.trusted.com/image.png",
        "http://evilimg.example.com/image.png",
    ],
    "userinfo_authority_confusion": [
        "http://cdn.trusted.com@127.0.0.1/admin/image.png",
        "http://img.example.com@169.254.169.254/latest/meta-data/",
        "http://images.hosting.com@[::1]/admin/",
    ],
    "untrusted_host_in_query_or_fragment": [
        "http://evil.invalid/image.png?next=cdn.trusted.com",
        "http://evil.invalid/image.png#img.example.com",
    ],
    "loopback_and_private_addresses": [
        "http://localhost/admin/image.png",
        "http://127.0.0.1/admin/image.png",
        "http://127.1/admin/image.png",
        "http://2130706433/admin/image.png",
        "http://[::1]/admin/image.png",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "alternate_schemes": [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "ftp://localhost/image.png",
    ],
    "parser_and_encoding_confusion": [
        "http://cdn.trusted.com\\@127.0.0.1/image.png",
        "http://%63dn.trusted.com.evil.invalid/image.png",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "http://cdn.trusted.com/photo.jpg",
        "https://img.example.com/assets/photo.png",
        "https://images.hosting.com/gallery/image.webp",
    ]

    if not fdp.ConsumeBool():
        return {"img_address": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
    if fuzz:
        payload += "/" + fuzz
    return {"img_address": payload}
