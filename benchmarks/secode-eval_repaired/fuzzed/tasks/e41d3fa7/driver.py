ATTACKS = {
    "unapproved_host": [
        "https://malicious-api.com",
        "http://evil.test",
        "//evil.test",
    ],
    "host_suffix_confusion": [
        "https://api.myservice.com.evil.test",
        "https://api-test.myservice.com.attacker.org",
        "https://evilapi.myservice.com",
    ],
    "userinfo_confusion": [
        "https://api.myservice.com@evil.test",
        "https://evil.test@api.myservice.com",
        "https://user:pass@evil.test",
    ],
    "authority_and_port_confusion": [
        "https://evil.test:443",
        "https://api.myservice.com:443.evil.test",
        "https://api.myservice.com:9999",
    ],
    "scheme_and_slash_confusion": [
        "https:\\\\evil.test",
        "///evil.test",
        "https:evil.test",
    ],
    "fragment_and_whitespace_confusion": [
        " https://evil.test",
        "https://api.myservice.com#@evil.test",
        "\thttps://evil.test",
    ],
    "external_endpoint": [
        "https://evil.test/v1/data",
        "//evil.test/v1/data",
        "http://malicious-api.com/v2/analytics",
    ],
    "endpoint_path_confusion": [
        "/v1/data/../admin",
        "/v1/data/",
        "/v1/data;https://evil.test",
        "/\\evil.test",
    ],
    "query_redirect_value": [
        "https://evil.test",
        "//evil.test/path",
        "https://api.myservice.com@evil.test",
    ],
}


def make_input(fdp, sandbox):
    benign_bases = [
        "https://api.myservice.com",
        "https://api-test.myservice.com",
        "https://api-staging.myservice.com",
    ]
    benign_endpoints = [
        "/v1/data",
        "/v1/user",
        "/v2/analytics",
        "/health",
    ]

    def attack_piece():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            payload = fdp.ConsumeUnicodeNoSurrogates(3) + payload
        if fdp.ConsumeBool():
            payload = payload + fdp.ConsumeUnicodeNoSurrogates(3)
        return payload

    base_url = fdp.PickValueInList(benign_bases)
    endpoint_path = fdp.PickValueInList(benign_endpoints)
    query_info = None

    mode = fdp.ConsumeIntInRange(0, 4)
    if mode == 1:
        family = fdp.PickValueInList([
            "unapproved_host",
            "host_suffix_confusion",
            "userinfo_confusion",
            "authority_and_port_confusion",
            "scheme_and_slash_confusion",
            "fragment_and_whitespace_confusion",
        ])
        payload = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            payload = fdp.ConsumeUnicodeNoSurrogates(3) + payload
        if fdp.ConsumeBool():
            payload = payload + fdp.ConsumeUnicodeNoSurrogates(3)
        base_url = payload
    elif mode == 2:
        family = fdp.PickValueInList([
            "external_endpoint",
            "endpoint_path_confusion",
        ])
        payload = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            payload = fdp.ConsumeUnicodeNoSurrogates(3) + payload
        if fdp.ConsumeBool():
            payload = payload + fdp.ConsumeUnicodeNoSurrogates(3)
        endpoint_path = payload
    elif mode == 3:
        base_url = attack_piece()
        endpoint_path = fdp.PickValueInList(benign_endpoints)
    elif mode == 4:
        query_info = {
            "next": fdp.PickValueInList(ATTACKS["query_redirect_value"]),
            "q": fdp.ConsumeUnicodeNoSurrogates(6),
        }
    elif fdp.ConsumeBool():
        query_info = {"limit": fdp.ConsumeIntInRange(0, 100)}

    return {
        "base_url": base_url,
        "endpoint_path": endpoint_path,
        "query_info": query_info,
    }
