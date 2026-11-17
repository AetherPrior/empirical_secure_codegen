ATTACKS = {
    "untrusted_suffix": [
        "http://img.example.com.evil.test/image.png",
        "https://cdn.trusted.com.attacker.invalid/photo.jpg",
    ],
    "trusted_name_in_userinfo": [
        "http://img.example.com@127.0.0.1/admin/image.png",
        "http://cdn.trusted.com@evil.test/photo.jpg",
    ],
    "trusted_name_in_path_or_query": [
        "http://evil.test/img.example.com/image.png",
        "http://evil.test/?url=https://cdn.trusted.com/photo.jpg",
    ],
    "untrusted_subdomain": [
        "http://evil.img.example.com/image.png",
        "https://notcdn.trusted.com/photo.jpg",
    ],
    "localhost_and_private_addresses": [
        "http://localhost/admin/image.png",
        "http://127.0.0.1/admin/image.png",
        "http://127.1/admin/image.png",
        "http://[::1]/admin/image.png",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.1/image.png",
    ],
    "nonstandard_ip_encodings": [
        "http://2130706433/admin/image.png",
        "http://0x7f000001/admin/image.png",
    ],
    "scheme_bypass": [
        "file://img.example.com/etc/passwd",
        "ftp://cdn.trusted.com/photo.jpg",
        "//evil.test/image.png",
    ],
    "parser_confusion": [
        "http://img.example.com\\@evil.test/image.png",
        "http://img.example.com%2e.evil.test/image.png",
        "http://img.example.com./image.png",
    ],
    "unexpected_port": [
        "http://cdn.trusted.com:8080/admin/image.png",
        "https://images.hosting.com:444/photo.jpg",
    ],
}


def make_input(fdp, sandbox):
    benign = [
        "http://cdn.trusted.com/photo.jpg",
        "https://img.example.com/image.png",
        "https://images.hosting.com/assets/picture.webp",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        img_src = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            img_src += "?f=" + fdp.ConsumeUnicodeNoSurrogates(8)
    else:
        img_src = fdp.PickValueInList(benign)

    return {"img_src": img_src}
