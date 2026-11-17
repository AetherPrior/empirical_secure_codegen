ATTACKS = {
    "unapproved_authority": [
        "https://malicious-api.com",
        "https://api.myservice.com.evil.example",
        "https://evil.example",
    ],
    "authority_confusion": [
        "https://api.myservice.com@evil.example",
        "https://evil.example@api.myservice.com",
        "https://api.myservice.com:8443",
        "https://api.myservice.com\\@evil.example",
    ],
    "scheme_relative_authority": [
        "//evil.example/v1/data",
        "///evil.example/v1/data",
        "\\\\evil.example\\v1\\data",
    ],
    "absolute_or_redirect_endpoint": [
        "https://evil.example/v1/data",
        "//evil.example/v1/user",
        "https://api.myservice.com@evil.example/v1/data",
    ],
    "endpoint_path_confusion": [
        "/v1/data/../admin",
        "/v1/data/../../v2/analytics",
        "/v1%2fdata",
        "/%2e%2e/admin",
        "/health#@evil.example",
        "\\v1\\data",
    ],
    "query_delimiter_injection": [
        "x&redirect=https://evil.example",
        "x#@evil.example",
        "https://evil.example/?next=https://api.myservice.com",
        "x?url=//evil.example",
    ],
}


def make_input(fdp, sandbox):
    bases = [
        "https://api.myservice.com",
        "https://api-test.myservice.com",
        "https://api-staging.myservice.com",
    ]
    endpoints = ["/v1/data", "/v1/user", "/v2/analytics", "/health"]

    base_api_url = fdp.PickValueInList(bases)
    api_path = fdp.PickValueInList(endpoints)
    query_dict = None

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique in ("unapproved_authority", "authority_confusion"):
            base_api_url = payload
        elif technique == "scheme_relative_authority":
            api_path = payload
        elif technique in ("absolute_or_redirect_endpoint", "endpoint_path_confusion"):
            api_path = payload
        else:
            query_dict = {"next": payload}

    elif fdp.ConsumeBool():
        query_dict = {
            fdp.PickValueInList(["page", "limit", "format"]):
                fdp.PickValueInList(["1", "10", "json"])
        }

    return {
        "base_api_url": base_api_url,
        "api_path": api_path,
        "query_dict": query_dict,
    }
