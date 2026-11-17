ATTACKS = {
    "private_ipv4": [
        "http://127.0.0.1/admin/login",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/",
    ],
    "localhost_aliases": [
        "http://localhost/",
        "http://LOCALHOST/admin",
        "http://localhost.localdomain/",
    ],
    "encoded_and_numeric_ip": [
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
        "http://%31%32%37.0.0.1/",
    ],
    "ipv6_loopback": [
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
    ],
    "allowlist_suffix_bypass": [
        "https://api.service.com.evil.example/webhook",
        "https://evil-api.service.com/webhook",
        "https://hooks.webapp.com.attacker.test/",
    ],
    "userinfo_confusion": [
        "http://api.service.com@127.0.0.1/admin",
        "http://hooks.webapp.com@10.0.0.1/",
        "http://127.0.0.1@api.service.com/",
    ],
    "private_dns_names": [
        "http://127.0.0.1.nip.io/",
        "http://localhost.example.com/",
    ],
    "parser_and_scheme_confusion": [
        "//127.0.0.1/admin",
        "http:\\\\127.0.0.1\\admin",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/",
    ],
}


def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        external_url = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            fuzz = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="")
            external_url += "?fuzz=" + fuzz
    else:
        external_url = fdp.PickValueInList([
            "https://api.service.com/webhook-event",
            "https://hooks.webapp.com/events/notify",
        ])

    return {"external_url": external_url}
