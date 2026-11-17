ATTACKS = {
    "loopback_and_private_ipv4": [
        "http://localhost/admin/image.png",
        "http://127.0.0.1/admin/image.png",
        "http://2130706433/admin/image.png",
        "http://0x7f000001/admin/image.png",
        "http://0177.0.0.1/admin/image.png",
        "http://192.168.1.1/image.png",
    ],
    "cloud_metadata": [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
    "loopback_ipv6": [
        "http://[::1]/admin/image.png",
        "http://[::ffff:127.0.0.1]/admin/image.png",
    ],
    "trusted_domain_suffix_confusion": [
        "http://cdn.trusted.com.evil.test/image.png",
        "http://img.example.com.attacker.test/image.png",
        "http://evil-cdn.trusted.com/image.png",
    ],
    "userinfo_host_confusion": [
        "http://cdn.trusted.com@127.0.0.1/image.png",
        "http://cdn.trusted.com@evil.test/image.png",
        "http://127.0.0.1@cdn.trusted.com.evil.test/image.png",
    ],
    "parser_and_encoding_confusion": [
        "http://cdn.trusted.com\\@127.0.0.1/image.png",
        "http://cdn.trusted.com%2e.evil.test/image.png",
        "http://cdn.trusted.com。evil.test/image.png",
    ],
    "untrusted_scheme": [
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/",
        "ftp://localhost/image.png",
    ],
    "relative_network_path": [
        "//localhost/admin/image.png",
        "//169.254.169.254/latest/meta-data/",
    ],
}

def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        image_link = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            suffix = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="")
            image_link += "/" + suffix
    else:
        host = fdp.PickValueInList([
            "img.example.com",
            "cdn.trusted.com",
            "images.hosting.com",
        ])
        path = quote(fdp.ConsumeUnicodeNoSurrogates(12), safe="")
        image_link = "https://" + host + "/image/" + path + ".png"

    return {"image_link": image_link}
