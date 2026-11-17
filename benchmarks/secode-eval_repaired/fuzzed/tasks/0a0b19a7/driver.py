ATTACKS = {
    "absolute_endpoint": [
        "https://evil.example/v1/data",
        "http://evil.example/v1/user",
    ],
    "protocol_relative_endpoint": [
        "//evil.example/v1/data",
        "///evil.example/v1/user",
    ],
    "authority_confusion": [
        "https://api.myservice.com.evil.example/v1/data",
        "https://api.myservice.com@evil.example/v1/data",
    ],
    "endpoint_path_escape": [
        "/v1/data/../admin",
        "/v1/user/../../redirect",
    ],
    "encoded_authority": [
        "%2f%2fevil.example/v1/data",
        "%252f%252fevil.example/v1/user",
    ],
    "backslash_authority": [
        r"\\evil.example\v1\data",
        r"/\evil.example/v1/user",
    ],
    "malicious_base": [
        "https://evil.example",
        "https://api.myservice.com.evil.example",
    ],
    "base_userinfo_confusion": [
        "https://api.myservice.com@evil.example",
        "https://evil.example@api.myservice.com",
    ],
    "query_redirect_value": [
        "https://evil.example/",
        "//evil.example/",
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

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        base = fdp.PickValueInList(benign_bases)
        endpoint = fdp.PickValueInList(benign_endpoints)
        query_params = None

        if family in ("absolute_endpoint", "protocol_relative_endpoint",
                      "authority_confusion", "endpoint_path_escape",
                      "encoded_authority", "backslash_authority"):
            endpoint = payload
        elif family in ("malicious_base", "base_userinfo_confusion"):
            base = payload
        else:
            query_params = {"next": payload}

        return {
            "api_base_url": base,
            "endpoint": endpoint,
            "query_params": query_params,
        }

    base = fdp.PickValueInList(benign_bases)
    endpoint = fdp.PickValueInList(benign_endpoints)
    query_params = None
    if fdp.ConsumeBool():
        query_params = {
            "limit": str(fdp.ConsumeIntInRange(1, 100)),
            "filter": fdp.ConsumeUnicodeNoSurrogates(8),
        }

    return {
        "api_base_url": base,
        "endpoint": endpoint,
        "query_params": query_params,
    }
