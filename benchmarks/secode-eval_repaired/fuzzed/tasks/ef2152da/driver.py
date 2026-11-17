ATTACKS = {
    "private_ipv4": [
        "http://127.0.0.1/admin/login",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/admin",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "localhost_aliases": [
        "http://localhost/admin",
        "http://localhost./admin",
        "http://127.1/admin",
        "http://0.0.0.0/admin",
    ],
    "userinfo_authority_confusion": [
        "https://api.service.com@127.0.0.1/admin",
        "https://hooks.webapp.com@localhost/internal",
    ],
    "allowlist_suffix_spoofing": [
        "https://api.service.com.attacker.example/event",
        "https://hooks.webapp.com.evil.test/event",
        "https://evil-api.service.com/event",
    ],
    "alternate_ip_notation": [
        "http://2130706433/admin",
        "http://0x7f000001/admin",
        "http://0177.0.0.1/admin",
    ],
    "ipv6_loopback": [
        "http://[::1]/admin",
        "http://[::ffff:127.0.0.1]/admin",
    ],
    "parser_disagreement": [
        "http://api.service.com\\@127.0.0.1/admin",
        "http://127.0.0.1\\@api.service.com/admin",
    ],
    "non_http_schemes": [
        "file://api.service.com/etc/passwd",
        "gopher://127.0.0.1:70/",
        "ftp://localhost/etc/passwd",
    ],
}


def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        callback_url = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            fuzz = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="")
            callback_url += "/fuzz-" + fuzz
    else:
        domain = fdp.PickValueInList(
            ["api.service.com", "hooks.webapp.com"]
        )
        path = quote(fdp.ConsumeUnicodeNoSurrogates(12), safe="")
        callback_url = "https://" + domain + "/events/" + path

    return {"callback_url": callback_url}
