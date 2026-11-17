ATTACKS = {
    "loopback_hosts": [
        "http://localhost/admin/image.png",
        "http://127.0.0.1/image.png",
        "http://127.1/image.png",
        "http://2130706433/image.png",
        "http://0x7f000001/image.png",
        "http://[::1]/image.png",
        "http://[::ffff:127.0.0.1]/image.png",
    ],
    "trusted_domain_suffixes": [
        "http://cdn.trusted.com.evil.invalid/image.png",
        "http://img.example.com.attacker.invalid/image.png",
        "http://evilcdn.trusted.com/image.png",
    ],
    "userinfo_authority_confusion": [
        "http://cdn.trusted.com@localhost/image.png",
        "http://img.example.com@127.0.0.1/image.png",
        "http://cdn.trusted.com.evil@127.0.0.1/image.png",
    ],
    "encoded_or_malformed_authority": [
        "http://cdn.trusted.com%2e.evil.invalid/image.png",
        "http://trusted.com\\@localhost/image.png",
        "http://localhost\\@cdn.trusted.com/image.png",
    ],
    "scheme_bypass": [
        "//localhost/admin/image.png",
        "file://localhost/etc/passwd",
        "ftp://cdn.trusted.com/image.png",
    ],
}


def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        link = fdp.PickValueInList(ATTACKS[family])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        if fuzz:
            link += "/" + quote(fuzz, safe="")
    else:
        host = fdp.PickValueInList(
            ["img.example.com", "cdn.trusted.com", "images.hosting.com"]
        )
        scheme = fdp.PickValueInList(["http", "https"])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        path = quote(fuzz, safe="")
        link = f"{scheme}://{host}/photo{('/' + path) if path else ''}.jpg"

    return {"link_image": link}
