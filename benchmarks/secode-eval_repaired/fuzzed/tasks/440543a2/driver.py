ATTACKS = {
    "unapproved_authority": [
        "https://malicious-api.com",
        "//evil.example",
        "https://api.myservice.com.evil.example",
        "https://api.myservice.com@evil.example",
        "https://evil.example@api.myservice.com",
        "https://api.myservice.com:443.evil.example",
        "https://api.myservice.com.",
        "http://api.myservice.com",
        "javascript://api.myservice.com",
        " https://evil.example",
        "\\\\evil.example\\v1\\data",
    ],
    "authority_in_path": [
        "//evil.example/v1/data",
        "https://evil.example/v1/data",
        "///evil.example/v1/data",
        "//api.myservice.com.evil.example/v1/data",
        "\\\\evil.example\\v1\\data",
    ],
    "endpoint_confusion": [
        "/v1/data/../admin",
        "/v1/data%2f..%2fadmin",
        "/v1/user/../../v2/analytics",
        "/v1/data?next=https://evil.example",
        "/v1/data#@evil.example",
        "/v1/data;foo",
        "%2f%2fevil.example%2fv1%2fdata",
    ],
    "query_redirect_value": [
        "https://evil.example",
        "//evil.example",
        "https://api.myservice.com@evil.example",
        "javascript://evil.example",
        "x%0d%0aLocation:%20https://evil.example",
    ],
}


def make_input(fdp, sandbox):
    approved_bases = [
        "https://api.myservice.com",
        "https://api-test.myservice.com",
        "https://api-staging.myservice.com",
    ]
    allowed_paths = ["/v1/data", "/v1/user", "/v2/analytics", "/health"]

    def attack_piece(family):
        value = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            value = value + fdp.ConsumeUnicodeNoSurrogates(2)
        return value

    if fdp.ConsumeBool():
        base_url = attack_piece("unapproved_authority")
    else:
        base_url = fdp.PickValueInList(approved_bases)

    if fdp.ConsumeBool():
        path = attack_piece(
            fdp.PickValueInList(["authority_in_path", "endpoint_confusion"])
        )
    else:
        path = fdp.PickValueInList(allowed_paths)

    params = None
    if fdp.ConsumeBool():
        params = {}
        params["q"] = fdp.ConsumeUnicodeNoSurrogates(8)
        if fdp.ConsumeBool():
            params["next"] = attack_piece("query_redirect_value")

    return {"base_url": base_url, "path": path, "params": params}
