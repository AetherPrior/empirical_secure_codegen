ATTACKS = {
    "loopback_host": [
        "http://localhost/admin/image.png",
        "http://127.0.0.1/image.png",
        "http://[::1]/image.png",
    ],
    "private_or_special_ip": [
        "http://10.0.0.1/image.png",
        "http://169.254.169.254/latest/meta-data/",
        "http://2130706433/image.png",
    ],
    "trusted_domain_suffix": [
        "http://cdn.trusted.com.evil.test/image.png",
        "http://img.example.com.attacker.invalid/image.png",
    ],
    "untrusted_subdomain_or_prefix": [
        "http://evil.cdn.trusted.com/image.png",
        "http://evilcdn.trusted.com/image.png",
    ],
    "userinfo_confusion": [
        "http://cdn.trusted.com@127.0.0.1/image.png",
        "http://img.example.com@evil.test/image.png",
    ],
    "scheme_confusion": [
        "ftp://cdn.trusted.com/image.png",
        "file:///etc/passwd",
        "javascript://cdn.trusted.com/image.png",
    ],
    "authority_parser_confusion": [
        "http://cdn.trusted.com\\@evil.test/image.png",
        "http://cdn%2etrusted.com/image.png",
        "//cdn.trusted.com/image.png",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        img_url = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(6)
            if suffix:
                img_url += "?q=" + suffix
    else:
        img_url = fdp.PickValueInList([
            "http://cdn.trusted.com/photo.jpg",
            "https://img.example.com/assets/image.png",
            "https://images.hosting.com/gallery/pic.webp",
        ])

    return {"img_url": img_url}
