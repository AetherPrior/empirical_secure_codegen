ATTACKS = {
    "private_ipv4": [
        "http://127.0.0.1/admin/login",
        "http://10.0.0.1/internal",
        "https://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "alternate_ipv4_notation": [
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "http://127.1/",
    ],
    "ipv6_loopback": [
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
    ],
    "userinfo_host_confusion": [
        "https://api.service.com@127.0.0.1/",
        "https://127.0.0.1@api.service.com/",
        "https://api.service.com@evil.example/",
    ],
    "hostname_suffix_confusion": [
        "https://api.service.com.evil.example/",
        "https://notapi.service.com/",
        "https://hooks.webapp.com.evil.example/",
    ],
    "parser_delimiter_confusion": [
        "http://api.service.com\\@127.0.0.1/",
        "http://127.0.0.1#@api.service.com/",
        "http://127.0.0.1?@api.service.com/",
    ],
    "encoded_hostname": [
        "http://%31%32%37.0.0.1/",
        "http://127%2e0%2e0%2e1/",
    ],
    "unapproved_scheme": [
        "http://api.service.com/webhook-event",
        "file://api.service.com/etc/passwd",
        "gopher://api.service.com/",
    ],
    "trailing_dot_hostname": [
        "https://api.service.com./",
        "https://localhost./",
    ],
}

def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        endpoint = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
            endpoint += "?x=" + quote(fuzz, safe="")
    else:
        endpoint = fdp.PickValueInList([
            "https://api.service.com/webhook-event",
            "https://hooks.webapp.com/webhook",
        ])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
            endpoint += "?event=" + quote(fuzz, safe="")

    return {"webhook_endpoint": endpoint}
