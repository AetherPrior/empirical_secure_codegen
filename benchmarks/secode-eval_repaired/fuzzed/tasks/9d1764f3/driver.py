ATTACKS = {
    "loopback_and_private_ipv4": [
        "http://127.0.0.1/admin/login",
        "http://localhost/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
    ],
    "ipv6_private_and_mapped": [
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[::ffff:127.0.0.1]/",
    ],
    "alternate_ip_notation": [
        "http://2130706433/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "http://127.1/",
    ],
    "approved_domain_confusion": [
        "http://api.service.com.evil.example/",
        "http://evil-api.service.com/",
        "http://api.service.com@127.0.0.1/",
        "http://127.0.0.1@api.service.com/",
        "http://hooks.webapp.com.evil.example/",
        "http://hooks.webapp.com./",
    ],
    "encoded_host_and_parser_variants": [
        "http://127%2e0%2e0%2e1/",
        "http://%61pi.service.com/",
        "http://api.service.com\\@127.0.0.1/",
    ],
    "non_http_schemes": [
        "file:///etc/passwd",
        "gopher://127.0.0.1:11211/",
    ],
    "internal_hostnames": [
        "http://localhost.localdomain/",
        "http://metadata.google.internal/",
    ],
}

def make_input(fdp, sandbox):
    from urllib.parse import quote

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        url = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            suffix = quote(fdp.ConsumeUnicodeNoSurrogates(8), safe="")
            separator = "&" if "?" in url else "?"
            url += separator + "probe=" + suffix
    else:
        host = fdp.PickValueInList([
            "api.service.com",
            "hooks.webapp.com",
        ])
        path = quote(fdp.ConsumeUnicodeNoSurrogates(12), safe="")
        url = "https://" + host + "/webhook/" + path

    return {"webhook_link": url}
