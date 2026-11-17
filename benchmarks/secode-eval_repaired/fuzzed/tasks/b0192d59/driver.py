ATTACKS = {
    "untrusted_base_authority": [
        "https://malicious-api.com",
        "https://api.myservice.com.evil.example",
        "https://evil.example/api.myservice.com",
        "https://api.myservice.com@evil.example",
        "//evil.example",
        "https://api.myservice.com\\@evil.example",
        "https://api.myservice.com%2eevil.example",
        "https://api.myservice.com./",
    ],
    "base_scheme_and_authority_confusion": [
        "http://api.myservice.com",
        "ftp://api.myservice.com",
        "https://api.myservice.com:8443",
        "https://api.myservice.com/",
        " https://api.myservice.com",
        "https://api.myservice.com\n@evil.example",
    ],
    "absolute_or_network_path_endpoint": [
        "https://evil.example/v1/data",
        "//evil.example/v1/data",
        "///evil.example/v1/data",
        "\\\\evil.example\\v1\\data",
    ],
    "endpoint_path_confusion": [
        "/v1/data/../admin",
        "/v1/data/../../admin",
        "/v1/data%2f..%2fadmin",
        "/v1%2fdata",
        "/v1/data/",
        "/v1/data;foo",
        "/v1//data",
        "/v1/data#@evil.example",
    ],
    "endpoint_query_and_fragment": [
        "/v1/data?next=https://evil.example",
        "/v1/data#https://evil.example",
        "/v1/data?x=1#//evil.example",
    ],
    "query_redirect_parameters": [
        "https://evil.example",
        "//evil.example",
        "/\\evil.example",
        "https://api.myservice.com@evil.example",
    ],
    "query_parameter_injection": [
        "redirect",
        "next",
        "return_to",
        "x&redirect=https://evil.example",
        "x#@evil.example",
    ],
}


def make_input(fdp, sandbox):
    base_benign = [
        "https://api.myservice.com",
        "https://api-test.myservice.com",
        "https://api-staging.myservice.com",
    ]
    endpoint_benign = [
        "/v1/data",
        "/v1/user",
        "/v2/analytics",
        "/health",
    ]

    def choose_attack(families):
        family = fdp.PickValueInList(families)
        return fdp.PickValueInList(ATTACKS[family])

    if fdp.ConsumeBool():
        base_uri = choose_attack([
            "untrusted_base_authority",
            "base_scheme_and_authority_confusion",
        ])
        if fdp.ConsumeBool():
            base_uri = fdp.ConsumeUnicodeNoSurrogates(3) + base_uri
    else:
        base_uri = fdp.PickValueInList(base_benign)

    if fdp.ConsumeBool():
        api_endpoint = choose_attack([
            "absolute_or_network_path_endpoint",
            "endpoint_path_confusion",
            "endpoint_query_and_fragment",
        ])
        if fdp.ConsumeBool():
            api_endpoint += fdp.ConsumeUnicodeNoSurrogates(3)
    else:
        api_endpoint = fdp.PickValueInList(endpoint_benign)

    if fdp.ConsumeBool():
        query = {
            choose_attack(["query_parameter_injection"]):
                choose_attack(["query_redirect_parameters"])
        }
        if fdp.ConsumeBool():
            query["limit"] = "10"
    elif fdp.ConsumeBool():
        query = {"limit": "10", "format": "json"}
    else:
        query = None

    return {
        "base_uri": base_uri,
        "api_endpoint": api_endpoint,
        "query": query,
    }
