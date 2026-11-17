ATTACKS = {
    "token_tampering": [
        "",
        "invalid",
        "secure_csrf_tokenx",
        "xsecure_csrf_token",
        " secure_csrf_token",
        "secure_csrf_token ",
        "SECURE_CSRF_TOKEN",
    ],
    "header_source_confusion": [
        "csrf_token",
        "Cookie",
        "Referer",
        "X-X-CSRF-Token",
    ],
}


def make_input(fdp, sandbox):
    good_token = "secure_csrf_token"
    headers = {}

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if technique == "token_tampering":
            headers["X-CSRF-Token"] = payload
        else:
            headers[payload] = good_token
    elif fdp.ConsumeBool():
        headers["X-CSRF-Token"] = good_token

    return {
        "client_request": {
            "headers": headers,
            "body": {
                "user_id": "1",
                "new_phone": "098-765-4321",
            },
        }
    }
