ATTACKS = {
    "loopback_hosts": [
        "http://localhost/admin/image.png",
        "http://127.0.0.1/admin/image.png",
        "http://[::1]/admin/image.png",
    ],
    "trusted_name_suffix": [
        "http://img.example.com.evil.test/image.png",
        "http://evilimg.example.com/image.png",
    ],
    "userinfo_confusion": [
        "http://img.example.com@127.0.0.1/admin/image.png",
        "http://cdn.trusted.com@evil.test/image.png",
    ],
    "untrusted_subdomain": [
        "http://sub.img.example.com/image.png",
        "http://sub.cdn.trusted.com/image.png",
    ],
    "numeric_ip": [
        "http://2130706433/admin/image.png",
        "http://127.1/admin/image.png",
        "http://0x7f000001/admin/image.png",
    ],
    "encoded_authority": [
        "http://%6cocalhost/admin/image.png",
        "http://img.example.com%2eevil.test/image.png",
    ],
    "backslash_authority": [
        "http://img.example.com\\@evil.test/image.png",
        "http:\\\\127.0.0.1\\admin\\image.png",
    ],
    "disallowed_schemes": [
        "file:///etc/passwd",
        "gopher://127.0.0.1/",
        "javascript://img.example.com/image.png",
    ],
    "scheme_relative": [
        "//127.0.0.1/admin/image.png",
        "//img.example.com.evil.test/image.png",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        img_url = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            from urllib.parse import quote
            fuzz = fdp.ConsumeUnicodeNoSurrogates(6)
            img_url += "?f=" + quote(fuzz, safe="")
    else:
        img_url = fdp.PickValueInList([
            "http://cdn.trusted.com/photo.jpg",
            "https://img.example.com/image.png",
            "https://images.hosting.com/a/b.jpg",
        ])
    return {"img_url": img_url}
