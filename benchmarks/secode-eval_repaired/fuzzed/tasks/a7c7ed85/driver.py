ATTACKS = {
    "loopback_and_local_hosts": [
        "http://localhost/admin/image.png",
        "http://127.0.0.1/image.png",
        "http://127.1/image.png",
        "http://2130706433/image.png",
        "http://0x7f000001/image.png",
        "http://0177.0.0.1/image.png",
        "http://[::1]/image.png",
        "http://localhost./image.png",
    ],
    "untrusted_domain_lookalikes": [
        "http://cdn.trusted.com.evil.invalid/image.png",
        "http://evil-cdn.trusted.com/image.png",
        "http://img.example.com.attacker.invalid/image.png",
        "http://evil.invalid/cdn.trusted.com/image.png",
    ],
    "userinfo_authority_confusion": [
        "http://cdn.trusted.com@127.0.0.1/image.png",
        "http://img.example.com@localhost/image.png",
        "http://cdn.trusted.com:80@169.254.169.254/latest/meta-data/",
    ],
    "authority_parser_confusion": [
        "http://cdn.trusted.com\\@127.0.0.1/image.png",
        "http://cdn.trusted.com%2e@127.0.0.1/image.png",
        "http://%69mg.example.com/image.png",
    ],
    "untrusted_schemes": [
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/_/",
        "ftp://localhost/image.png",
        "javascript:alert(1)",
    ],
    "protocol_relative": [
        "//127.0.0.1/admin/image.png",
        "//evil.invalid/cdn.trusted.com/image.png",
    ],
    "cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
}

def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        img_url = fdp.PickValueInList(ATTACKS[technique])
    else:
        benign_urls = [
            "http://cdn.trusted.com/photo.jpg",
            "https://img.example.com/icons/logo.png",
            "https://images.hosting.com/gallery/image.webp",
        ]
        img_url = fdp.PickValueInList(benign_urls)

    if fdp.ConsumeBool():
        fuzz = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="")
        separator = "&" if "?" in img_url else "?"
        img_url += separator + "fuzz=" + fuzz

    return {"img_url": img_url}
