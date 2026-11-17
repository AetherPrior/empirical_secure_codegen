ATTACKS = {
    "loopback_ipv4": [
        "http://127.0.0.1/admin/login",
        "http://127.1/admin/",
        "http://2130706433/admin/",
        "http://0x7f000001/admin/",
    ],
    "private_ipv4": [
        "http://10.0.0.1/internal",
        "http://192.168.1.1/admin",
        "http://172.16.0.1/private",
    ],
    "loopback_ipv6": [
        "http://[::1]/admin",
        "http://[::ffff:127.0.0.1]/admin",
        "http://[fe80::1%25lo0]/admin",
    ],
    "internal_hostnames": [
        "http://localhost/admin",
        "http://localhost./admin",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
    "allowlist_suffix_confusion": [
        "https://api.service.com.evil.example/webhook",
        "https://hooks.webapp.com.attacker.example/callback",
        "https://evil-api.service.com/webhook",
    ],
    "userinfo_authority_confusion": [
        "https://api.service.com@127.0.0.1/admin",
        "https://hooks.webapp.com@10.0.0.1/admin",
        "https://api.service.com@evil.example/webhook",
    ],
    "parser_confusion": [
        "http://api.service.com\\@127.0.0.1/admin",
        "http://127.0.0.1%2f@api.service.com/admin",
        "http://%31%32%37.0.0.1/admin",
    ],
    "unsupported_schemes": [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "ftp://10.0.0.1/private",
    ],
    "dns_aliases": [
        "http://127.0.0.1.nip.io/admin",
        "http://localhost.evil.example/admin",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        "https://api.service.com/webhook-event",
        "https://hooks.webapp.com/callback",
        "https://api.service.com/v1/hooks/notify",
    ]

    if not fdp.ConsumeBool():
        return {"hook_url": fdp.PickValueInList(benign)}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    # Preserve the attack URL while varying its path/query text.
    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        payload += ("&" if "?" in payload else "?") + "fuzz=" + fuzz

    return {"hook_url": payload}
