ATTACKS = {
    "direct_private_hosts": [
        "http://127.0.0.1/admin/login",
        "http://localhost/admin",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/admin",
        "http://172.16.0.1/private",
    ],
    "alternate_ip_encodings": [
        "http://2130706433/admin",
        "http://0177.0.0.1/admin",
        "http://0x7f000001/admin",
        "http://[::1]/admin",
        "http://[::ffff:127.0.0.1]/admin",
    ],
    "allowlist_suffix_and_prefix": [
        "https://api.service.com.attacker.invalid/webhook",
        "https://attacker.invalid/api.service.com/webhook",
        "https://api.service.com@attacker.invalid/webhook",
        "https://hooks.webapp.com.evil.invalid/webhook",
    ],
    "userinfo_host_confusion": [
        "http://api.service.com@127.0.0.1/admin",
        "http://hooks.webapp.com@10.0.0.1/private",
        "https://127.0.0.1@api.service.com/webhook",
    ],
    "scheme_and_parser_confusion": [
        "file://127.0.0.1/etc/passwd",
        "gopher://127.0.0.1:70/",
        "//127.0.0.1/admin",
        "http:\\\\127.0.0.1\\admin",
        "http://127.0.0.1%2f@api.service.com/admin",
    ],
    "hostname_normalization": [
        "https://api.service.com./webhook",
        "https://API.SERVICE.COM/webhook",
        "https://api%2eservice.com/webhook",
        "https://localhost./admin",
        "http://127.1/admin",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        address = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(8)
            if suffix:
                address += "?" + suffix
    else:
        address = fdp.PickValueInList([
            "https://api.service.com/webhook-event",
            "https://hooks.webapp.com/events",
            "https://api.service.com/v1/hooks?event=created",
        ])
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(8)
            if suffix:
                address += "/" + suffix

    return {"webhook_address": address}
