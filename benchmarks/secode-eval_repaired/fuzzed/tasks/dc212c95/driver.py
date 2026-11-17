ATTACKS = {
    "direct_private_addresses": [
        "http://127.0.0.1/admin/login",
        "http://localhost/admin",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/",
    ],
    "alternate_ip_notations": [
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "http://127.1/",
        "http://%31%32%37.0.0.1/",
    ],
    "ipv6_and_mapped_addresses": [
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[fe80::1]/",
    ],
    "hostname_whitelist_confusion": [
        "https://api.service.com.evil.test/",
        "https://hooks.webapp.com.attacker.test/",
        "https://api.service.com./",
        "https://api.service.com%2e.evil.test/",
        "https://api。service.com/",
    ],
    "userinfo_authority_confusion": [
        "https://api.service.com@127.0.0.1/",
        "https://api.service.com@localhost/",
        "https://127.0.0.1@api.service.com/",
        "https://api.service.com:443@localhost/",
    ],
    "backslash_and_delimiter_confusion": [
        "http://api.service.com\\@127.0.0.1/",
        "https://api.service.com\\evil.test/",
        "https://api.service.com%2f@127.0.0.1/",
    ],
    "scheme_and_case_variants": [
        "http://api.service.com/",
        "HTTPS://API.SERVICE.COM/",
        "https:////api.service.com/",
        "//127.0.0.1/admin",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "https://api.service.com/webhook-event",
        "https://hooks.webapp.com/events/receive",
        "https://api.service.com/v1/hooks?id=7",
    ]

    if not fdp.ConsumeBool():
        endpoint = fdp.PickValueInList(benign)
    else:
        family = fdp.PickValueInList(sorted(ATTACKS))
        endpoint = fdp.PickValueInList(ATTACKS[family])

        mode = fdp.ConsumeIntInRange(0, 3)
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        if mode == 1:
            separator = "&" if "?" in endpoint else "?"
            endpoint += separator + "x=" + fuzz
        elif mode == 2:
            endpoint = fuzz + endpoint
        elif mode == 3:
            endpoint += fuzz

    return {"webhook_endpoint": endpoint}
