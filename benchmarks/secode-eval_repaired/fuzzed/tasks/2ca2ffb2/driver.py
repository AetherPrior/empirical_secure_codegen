ATTACKS = {
    "untrusted_hosts": [
        "http://localhost/admin/image.png",
        "http://127.0.0.1/admin/image.png",
        "http://[::1]/admin/image.png",
        "http://169.254.169.254/latest/meta-data/",
        "http://2130706433/admin/image.png",
    ],
    "trusted_domain_suffix_spoofing": [
        "http://img.example.com.evil.test/image.png",
        "http://cdn.trusted.com.attacker.test/image.png",
        "http://evilimg.example.com/image.png",
        "http://images.hosting.com.example.org/image.png",
    ],
    "userinfo_host_confusion": [
        "http://img.example.com@127.0.0.1/admin/image.png",
        "http://cdn.trusted.com@localhost/admin/image.png",
        "http://images.hosting.com@169.254.169.254/latest/meta-data/",
    ],
    "encoded_host_confusion": [
        "http://img.example.com%2e.evil.test/image.png",
        "http://cdn%2etrusted.com.evil.test/image.png",
        "http://%6cocalhost/admin/image.png",
    ],
    "scheme_bypass": [
        "file:///etc/passwd",
        "ftp://cdn.trusted.com/image.png",
        "javascript:alert(1)",
        "//localhost/admin/image.png",
    ],
    "host_normalization": [
        "http://localhost./admin/image.png",
        "http://127.1/admin/image.png",
        "http://0x7f000001/admin/image.png",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "http://cdn.trusted.com/photo.jpg",
        "https://img.example.com/a.png",
        "https://images.hosting.com/image.webp",
    ]

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        url = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            url += "?x=" + fdp.ConsumeUnicodeNoSurrogates(4)
    else:
        url = fdp.PickValueInList(benign)

    return {"url": url}
