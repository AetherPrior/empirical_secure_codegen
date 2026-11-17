ATTACKS = {
    "loopback_hosts": [
        "http://localhost/admin/image.png",
        "http://127.0.0.1/image.png",
        "http://[::1]/image.png",
        "http://2130706433/image.png",
        "http://0x7f000001/image.png",
    ],
    "trusted_host_suffix": [
        "http://cdn.trusted.com.attacker.invalid/image.png",
        "http://img.example.com.evil.test/image.png",
        "http://images.hosting.com.attacker.invalid/image.png",
    ],
    "userinfo_host_confusion": [
        "http://cdn.trusted.com@127.0.0.1/image.png",
        "http://attacker.invalid@cdn.trusted.com/image.png",
    ],
    "host_format_variants": [
        "http://cdn.trusted.com./image.png",
        "http://cdn%2etrusted.com/image.png",
        "http://cdn.trusted.com\\@127.0.0.1/image.png",
    ],
    "untrusted_scheme": [
        "file://cdn.trusted.com/etc/passwd",
        "ftp://cdn.trusted.com/image.png",
        "javascript://cdn.trusted.com/image.png",
    ],
    "untrusted_hosts": [
        "http://localhost/admin/image.png",
        "http://192.168.1.1/image.png",
        "http://169.254.169.254/latest/meta-data/",
        "http://attacker.invalid/image.png",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        pic_url = fdp.PickValueInList(ATTACKS[technique])
    else:
        pic_url = fdp.PickValueInList([
            "http://cdn.trusted.com/photo.jpg",
            "https://img.example.com/picture.png",
            "http://images.hosting.com/avatar.webp",
        ])

    return {"pic_url": pic_url}
