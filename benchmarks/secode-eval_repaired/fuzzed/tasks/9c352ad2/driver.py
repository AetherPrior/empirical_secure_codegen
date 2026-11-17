ATTACKS = {
    "private_ipv4": [
        "http://127.0.0.1/admin/login",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/",
        "http://127.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://0177.0.0.1/",
    ],
    "private_ipv6": [
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
    ],
    "userinfo_host_confusion": [
        "http://api.service.com@127.0.0.1/",
        "http://api.service.com@localhost/",
        "http://127.0.0.1@api.service.com/",
    ],
    "approved_domain_suffix": [
        "https://api.service.com.evil.test/",
        "https://evilapi.service.com/",
        "https://api.service.com.attacker.example/",
        "https://api.service.com%2e.evil.test/",
    ],
    "localhost_name_confusion": [
        "http://localhost.attacker.test/",
        "http://localhost./",
    ],
    "hostname_normalization": [
        "https://api.service.com./",
        "https://api%2eservice.com/",
        "https://api。service.com/",
    ],
    "url_parser_confusion": [
        "http://api.service.com\\@127.0.0.1/",
        "//127.0.0.1/admin",
        "http:127.0.0.1/admin",
    ],
    "unsafe_scheme": [
        "file:///etc/passwd",
        "gopher://127.0.0.1/",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        url = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
            url += "?probe=" + fuzz
    else:
        url = fdp.PickValueInList([
            "https://api.service.com/webhook-event",
            "https://hooks.webapp.com/webhook-event",
        ])
    return {"webhook_url": url}
