ATTACKS = {
    "authority_spoofing": [
        "https://api.myservice.com.evil.example",
        "https://api.myservice.com@evil.example",
        "https://evil.example#@api.myservice.com",
        "https://api.myservice.com:443.evil.example",
        "https://api.myservice.com./",
    ],
    "scheme_relative_authority": [
        "//evil.example/path",
        "///evil.example/path",
        "\\\\evil.example\\path",
    ],
    "unapproved_scheme_or_host": [
        "http://api.myservice.com",
        "https://evil.example",
        "https://api-test.myservice.com.evil.example",
    ],
    "absolute_endpoint": [
        "https://evil.example/v1/data",
        "//evil.example/v1/data",
        "https://api.myservice.com@evil.example/v1/data",
    ],
    "endpoint_path_confusion": [
        "/v1/data/../admin",
        "/v1/data%2f..%2fadmin",
        "/%2f%2fevil.example",
        "/v1/data#@evil.example",
        "/v1/data?next=https://evil.example",
        "/v1/data\\..\\admin",
    ],
    "redirect_query_value": [
        "https://evil.example/",
        "//evil.example/",
        "javascript:alert(1)",
        "https://api.myservice.com@evil.example/",
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

    base_url_api = fdp.PickValueInList(benign_bases)
    desired_endpoint = fdp.PickValueInList(benign_endpoints)
    optional_params = None

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if fdp.ConsumeBool():
            noise = fdp.ConsumeUnicodeNoSurrogates(3)
            if fdp.ConsumeBool():
                payload = noise + payload
            else:
                payload = payload + noise

        if technique in (
            "authority_spoofing",
            "scheme_relative_authority",
            "unapproved_scheme_or_host",
        ):
            base_url_api = payload
        elif technique in ("absolute_endpoint", "endpoint_path_confusion"):
            desired_endpoint = payload
        else:
            optional_params = {"next": payload}

    if optional_params is None and fdp.ConsumeBool():
        optional_params = {
            "limit": str(fdp.ConsumeIntInRange(1, 100)),
            "format": fdp.PickValueInList(["json", "compact"]),
        }

    return {
        "base_url_api": base_url_api,
        "desired_endpoint": desired_endpoint,
        "optional_params": optional_params,
    }
