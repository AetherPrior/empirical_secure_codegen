ATTACKS = {
    "untrusted_authority": [
        "https://malicious-api.com",
        "https://api.myservice.com.evil.example",
        "https://evil.example/api.myservice.com",
        "https://api.myservice.com@evil.example",
        "https://evil.example@api.myservice.com",
        "https://evil.example#@api.myservice.com",
        "https://api.myservice.com./",
        "https://%61pi.myservice.com",
        "//evil.example",
        "https://api.myservice.com:444",
    ],
    "endpoint_authority_override": [
        "https://evil.example/v1/data",
        "//evil.example/v1/data",
        r"\\evil.example\v1\data",
        "/\\evil.example/v1/data",
        "%2f%2fevil.example/v1/data",
    ],
    "endpoint_path_confusion": [
        "/v1/data/../admin",
        "/v1/data/../../v1/user",
        "/v1/data/",
        "/v1/data?next=https://evil.example",
        "/v1/data#@evil.example",
        "/v1%2f..%2fadmin",
    ],
    "query_redirect_values": [
        "//evil.example",
        "https://evil.example/",
        "/v1/data#@evil.example",
    ],
    "query_redirect_keys": [
        "redirect",
        "next",
        "url",
    ],
}


def make_input(fdp, sandbox):
    approved_bases = [
        "https://api.myservice.com",
        "https://api-test.myservice.com",
        "https://api-staging.myservice.com",
    ]
    allowed_endpoints = [
        "/v1/data",
        "/v1/user",
        "/v2/analytics",
        "/health",
    ]

    base_api_url = fdp.PickValueInList(approved_bases)
    api_endpoint = fdp.PickValueInList(allowed_endpoints)

    if fdp.ConsumeBool():
        target = fdp.ConsumeIntInRange(0, 2)
        if target in (0, 2):
            base_api_url = fdp.PickValueInList(ATTACKS["untrusted_authority"])
        if target in (1, 2):
            family = fdp.PickValueInList([
                "endpoint_authority_override",
                "endpoint_path_confusion",
            ])
            api_endpoint = fdp.PickValueInList(ATTACKS[family])

    query_options = None
    if fdp.ConsumeBool():
        query_options = {
            "limit": "10",
            "format": "json",
        }
        if fdp.ConsumeBool():
            key = fdp.PickValueInList(ATTACKS["query_redirect_keys"])
            value = fdp.PickValueInList(ATTACKS["query_redirect_values"])
            query_options[key] = value

    return {
        "base_api_url": base_api_url,
        "api_endpoint": api_endpoint,
        "query_options": query_options,
    }
