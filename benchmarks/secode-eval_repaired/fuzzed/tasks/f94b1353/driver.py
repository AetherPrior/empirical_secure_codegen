ATTACKS = {
    "direct_internal_ipv4": [
        "http://127.0.0.1/admin/login",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/admin",
        "http://localhost/",
    ],
    "allowlist_suffix_spoofing": [
        "https://api.service.com.evil.example/webhook",
        "https://evil-api.service.com/webhook",
        "https://hooks.webapp.com.attacker.test/event",
    ],
    "userinfo_authority_confusion": [
        "https://api.service.com@127.0.0.1/admin",
        "https://api.service.com@10.0.0.2/internal",
        "https://hooks.webapp.com@evil.example/event",
    ],
    "nonstandard_ip_notations": [
        "http://2130706433/admin",
        "http://0x7f000001/admin",
        "http://0177.0.0.1/admin",
        "http://127.1/admin",
    ],
    "ipv6_loopback": [
        "http://[::1]/admin",
        "http://[::ffff:127.0.0.1]/admin",
    ],
    "encoded_authority": [
        "http://127%2e0%2e0%2e1/admin",
        "http://%31%32%37.0.0.1/admin",
        "https://api.service.com%2f@127.0.0.1/admin",
    ],
    "backslash_authority_confusion": [
        "http://127.0.0.1\\@api.service.com/admin",
        "https://api.service.com\\@127.0.0.1/admin",
    ],
    "scheme_and_authority_variants": [
        "//127.0.0.1/admin",
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/_admin",
        "HTTP://127.0.0.1/admin",
    ],
    "internal_host_suffix_and_dns": [
        "http://127.0.0.1.nip.io/admin",
        "http://localhost.evil.example/admin",
        "http://10.example.test/internal",
    ],
    "approved_domain_endpoint_variants": [
        "https://api.service.com:8080/webhook",
        "https://api.service.com./webhook",
        "https://sub.api.service.com/webhook",
    ],
}


def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        url_hook = fdp.PickValueInList(ATTACKS[family])
    else:
        url_hook = fdp.PickValueInList([
            "https://api.service.com/webhook-event",
            "https://hooks.webapp.com/events",
        ])

    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(6)
        if fuzz:
            separator = "&" if "?" in url_hook else "?"
            url_hook += separator + "fuzz=" + quote(fuzz, safe="")

    return {"url_hook": url_hook}
