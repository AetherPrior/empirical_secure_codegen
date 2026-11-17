ATTACKS = {
    "untrusted_authority": [
        "https://malicious-api.com",
        "https://api.myservice.com.evil.test",
        "https://api.myservice.com@evil.test",
        "https://evil.test@api.myservice.com",
        "//evil.test",
        "https://api.myservice.com%2eevil.test",
    ],
    "authority_parser_confusion": [
        "https://api.myservice.com\\@evil.test",
        "https://api.myservice.com:443@evil.test",
        "https://api.myservice.com.evil.test/",
    ],
    "absolute_endpoint": [
        "https://evil.test/path",
        "//evil.test/path",
        "\\\\evil.test\\path",
    ],
    "endpoint_path_escape": [
        "/v1/data/../admin",
        "/v1/data/../../v1/user",
        "/v1/data%2f..%2fadmin",
    ],
    "query_injection": [
        "https://evil.test/",
        "//evil.test/",
        "#https://evil.test/",
        "&next=https://evil.test/",
    ],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        main_url = fdp.PickValueInList([
            "https://api.myservice.com",
            "https://api-test.myservice.com",
            "https://api-staging.myservice.com",
        ])
        endpoint_name = fdp.PickValueInList([
            "/v1/data", "/v1/user", "/v2/analytics", "/health",
        ])
        params_dict = (
            {"limit": "10", "q": fdp.ConsumeUnicodeNoSurrogates(8)}
            if fdp.ConsumeBool()
            else None
        )
        return {
            "main_url": main_url,
            "endpoint_name": endpoint_name,
            "params_dict": params_dict,
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    fuzz = fdp.ConsumeUnicodeNoSurrogates(6)

    main_url = fdp.PickValueInList([
        "https://api.myservice.com",
        "https://api-test.myservice.com",
        "https://api-staging.myservice.com",
    ])
    endpoint_name = fdp.PickValueInList([
        "/v1/data", "/v1/user", "/v2/analytics", "/health",
    ])
    params_dict = None

    if technique in ("untrusted_authority", "authority_parser_confusion"):
        main_url = payload if fdp.ConsumeBool() else payload + fuzz
    elif technique in ("absolute_endpoint", "endpoint_path_escape"):
        endpoint_name = payload if fdp.ConsumeBool() else fuzz + payload
    else:
        params_dict = {
            fdp.PickValueInList(["next", "redirect", "return_url"]):
                payload if fdp.ConsumeBool() else fuzz + payload
        }

    return {
        "main_url": main_url,
        "endpoint_name": endpoint_name,
        "params_dict": params_dict,
    }
