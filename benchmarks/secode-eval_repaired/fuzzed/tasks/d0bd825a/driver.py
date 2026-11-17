ATTACKS = {
    "untrusted_authority": [
        "https://malicious-api.com",
        "https://api.myservice.com.evil.example",
        "https://api.myservice.com@evil.example",
        "https://evil.example@api.myservice.com",
        "https://api.myservice.com:8443",
        "http://api.myservice.com",
        "https://api.myservice.com\\@evil.example",
        "https://api.myservice.com%2eevil.example",
    ],
    "scheme_relative_authority": [
        "//evil.example",
        "///evil.example/v1/data",
        "//api.myservice.com.evil.example/v1/data",
    ],
    "absolute_endpoint": [
        "https://evil.example/v1/data",
        "http://evil.example/health",
        "//evil.example/v1/user",
    ],
    "endpoint_path_escape": [
        "/v1/data/../admin",
        "/v1/user/../../admin",
        "/v1/data/",
        "/health/extra",
        "/V1/data",
        "\\\\evil.example\\v1\\data",
    ],
    "endpoint_encoding_and_delimiters": [
        "/v1/data%2f..%2fadmin",
        "/v1%2fuser",
        "/health?next=https://evil.example",
        "/v1/data#@evil.example",
    ],
    "query_redirect_value": [
        "https://evil.example/",
        "//evil.example/",
        "/\\evil.example",
        "safe&next=https://evil.example",
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
        base_url_api = fdp.PickValueInList(ATTACKS["untrusted_authority"])
    elif fdp.ConsumeBool():
        base_url_api = fdp.PickValueInList(ATTACKS["scheme_relative_authority"])
    else:
        base_url_api = fdp.PickValueInList(benign_bases)

    endpoint_attack_families = [
        "absolute_endpoint",
        "endpoint_path_escape",
        "endpoint_encoding_and_delimiters",
    ]
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(endpoint_attack_families)
        api_endpoint = fdp.PickValueInList(ATTACKS[family])
    else:
        api_endpoint = fdp.PickValueInList(benign_endpoints)

    if fdp.ConsumeBool():
        opts = {
            fdp.PickValueInList(["next", "redirect", "redirect_uri"]):
                fdp.PickValueInList(ATTACKS["query_redirect_value"])
        }
    elif fdp.ConsumeBool():
        opts = {"limit": fdp.PickValueInList(["1", "10", "25"])}
    else:
        opts = None

    return {
        "base_url_api": base_url_api,
        "api_endpoint": api_endpoint,
        "opts": opts,
    }
