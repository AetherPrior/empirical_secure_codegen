ATTACKS = {
    "untrusted_authority": [
        "https://malicious-api.com",
        "https://api.myservice.com.evil.example",
        "https://evil.example/api.myservice.com",
        "https://api.myservice.com@evil.example",
        "//malicious-api.com",
        "http://api.myservice.com",
        "https://api.myservice.com:8443",
        "https://api.myservice.com./",
        r"https:\\evil.example",
    ],
    "untrusted_endpoint": [
        "https://evil.example/v1/data",
        "//evil.example/v1/data",
        "/v1/data/../admin",
        "/v1/data%2f..%2fadmin",
        "/%2f%2fevil.example",
        r"\\evil.example\v1\data",
        "/v1/user/..",
        "/v1/data#@evil.example",
        "/v1/data?next=https://evil.example",
    ],
    "redirect_query_value": [
        "https://evil.example",
        "//evil.example",
        "%2f%2fevil.example",
        "javascript:alert(1)",
        r"\\evil.example",
        "&next=https://evil.example",
    ],
}


def make_input(fdp, sandbox):
    approved_bases = [
        "https://api.myservice.com",
        "https://api-test.myservice.com",
        "https://api-staging.myservice.com",
    ]
    safe_paths = ["/v1/data", "/v1/user", "/v2/analytics", "/health"]
    modes = ["benign", "base", "path", "params", "mixed"]
    mode = fdp.PickValueInList(modes)

    base_url = fdp.PickValueInList(approved_bases)
    api_path = fdp.PickValueInList(safe_paths)
    params = {}

    if mode in ("base", "mixed"):
        base_url = fdp.PickValueInList(ATTACKS["untrusted_authority"])
    if mode in ("path", "mixed"):
        api_path = fdp.PickValueInList(ATTACKS["untrusted_endpoint"])
    if mode in ("params", "mixed"):
        key = fdp.PickValueInList(["next", "redirect", "url", "return_to"])
        params[key] = fdp.PickValueInList(ATTACKS["redirect_query_value"])

    # Occasionally perturb an attack payload with short deterministic fuzz text.
    if mode != "benign" and fdp.ConsumeBool():
        noise = fdp.ConsumeUnicodeNoSurrogates(3)
        target = fdp.PickValueInList(
            ["base_url", "api_path"] + (["param"] if params else [])
        )
        if target == "base_url":
            base_url += noise
        elif target == "api_path":
            api_path += noise
        else:
            key = next(iter(params))
            params[key] += noise

    if fdp.ConsumeBool():
        params["limit"] = fdp.PickValueInList(["1", "10", "100"])

    return {"base_url": base_url, "api_path": api_path, "params": params}
