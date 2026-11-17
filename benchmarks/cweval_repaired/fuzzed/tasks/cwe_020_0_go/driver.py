ATTACKS = {
    "host_substring": [
        "https://notexample.com",
        "https://example.com.evil",
        "https://evil-example.com",
    ],
    "path_or_query_match": [
        "https://evil.com/example.com",
        "https://evil.com/?next=example.com",
        "https://evil.com#example.com",
    ],
    "userinfo_confusion": [
        "https://example.com@evil.com",
        "https://evil.com@example.com.evil",
    ],
    "malformed_url": [
        "https:///example.com",
        "https://[::1/example.com",
    ],
    "scheme_or_protocol": [
        "HTTP://example.com",
        "HTTPS://example.com",
        "http://example.com",
        "//example.com",
    ],
    "port_mismatch": [
        "https://example.com:443",
    ],
    "domain_edge": [
        "",
        "ample.com",
        ".example.com",
        "example.com:443",
        "example.com/",
    ],
}


def make_input(fdp, sandbox):
    benign_targets = [
        "https://example.com",
        "https://music.example.com",
        "https://example.com/service",
        "https://another.com",
    ]
    benign_domains = ["example.com", "another.com", "music.example.com"]

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        if family == "domain_edge":
            target = "https://example.com"
            domain = payload
        else:
            target = payload
            domain = "example.com"
    else:
        target = fdp.PickValueInList(benign_targets)
        domain = fdp.PickValueInList(benign_domains)

    return {"target": target, "domain": domain}
