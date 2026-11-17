ATTACKS = {
    "trusted_suffix": [
        "http://img.example.com.evil.invalid/image.png",
        "https://cdn.trusted.com.attacker.test/photo.jpg",
        "http://images.hosting.com.evil.test/a.png",
    ],
    "trusted_in_path_or_query": [
        "http://evil.test/img.example.com/image.png",
        "https://evil.test/?next=https://cdn.trusted.com/photo.jpg",
    ],
    "userinfo_confusion": [
        "http://img.example.com@evil.test/image.png",
        "https://cdn.trusted.com@127.0.0.1/admin",
    ],
    "loopback_and_private_addresses": [
        "http://localhost/admin/image.png",
        "http://127.0.0.1/image.png",
        "http://[::1]/image.png",
        "http://192.168.1.1/image.png",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "alternate_ip_forms": [
        "http://2130706433/image.png",
        "http://0177.0.0.1/image.png",
        "http://0x7f000001/image.png",
    ],
    "scheme_bypass": [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "ftp://localhost/image.png",
    ],
    "authority_parser_confusion": [
        "http://img.example.com\\@evil.test/image.png",
        "http://img.example.com%2eevil.test/image.png",
        "http://img.example.com%00.evil.test/image.png",
    ],
    "hostname_normalization": [
        "http://img.example.com./image.png",
        "http://IMG.EXAMPLE.COM.evil.test/image.png",
        "http://іmg.example.com/image.png",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "http://cdn.trusted.com/photo.jpg",
        "https://img.example.com/image.png",
        "https://images.hosting.com/gallery/a.png",
    ]

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        image_url = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            extra = fdp.ConsumeUnicodeNoSurrogates(8)
            if extra:
                separator = "&" if "?" in image_url else "?"
                image_url += separator + "q=" + extra
    else:
        image_url = fdp.PickValueInList(benign)

    return {"image_url": image_url}
