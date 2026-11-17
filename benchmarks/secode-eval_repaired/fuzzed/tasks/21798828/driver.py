ATTACKS = {
    "userinfo_confusion": [
        "http://api.service.com@127.0.0.1/admin",
        "http://api.service.com@169.254.169.254/latest/meta-data/",
        "http://127.0.0.1@api.service.com/webhook-event",
        "http://api.service.com:80@10.0.0.1/",
    ],
    "suffix_and_prefix_domains": [
        "http://api.service.com.attacker.invalid/",
        "http://notapi.service.com/",
        "http://hooks.webapp.com.attacker.invalid/",
    ],
    "alternate_ipv4": [
        "http://2130706433/admin",
        "http://0177.0.0.1/admin",
        "http://0x7f000001/admin",
        "http://127.1/admin",
        "http://0/admin",
    ],
    "private_and_link_local_addresses": [
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/",
    ],
    "ipv6_loopback": [
        "http://[::1]/admin",
        "http://[::ffff:127.0.0.1]/admin",
        "http://[::ffff:7f00:1]/admin",
    ],
    "localhost_variants": [
        "http://localhost/admin",
        "http://localhost./admin",
        "http://127.0.0.1./admin",
    ],
    "parser_and_scheme_confusion": [
        "http://api.service.com\\@127.0.0.1/",
        "http://api.service.com%2f@127.0.0.1/",
        "http://api.service.com\n@127.0.0.1/",
        "file://127.0.0.1/etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "//127.0.0.1/admin",
    ],
}


def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        webhook_link = fdp.PickValueInList(ATTACKS[technique])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(8)
        if fuzz:
            separator = "&" if "?" in webhook_link else "?"
            webhook_link += separator + "fuzz=" + quote(fuzz, safe="")
    else:
        webhook_link = fdp.PickValueInList([
            "https://api.service.com/webhook-event",
            "https://hooks.webapp.com/events",
            "https://api.service.com/",
        ])

    return {"webhook_link": webhook_link}
