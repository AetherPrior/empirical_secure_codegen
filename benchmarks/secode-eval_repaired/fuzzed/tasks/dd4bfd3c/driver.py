ATTACKS = {
    "missing_header": [""],
    "invalid_token": [
        "invalid",
        "wrong_csrf_token",
        "secure_csrf_tokenx",
        " secure_csrf_token",
        "secure_csrf_token ",
    ],
}


def make_input(fdp, sandbox):
    headers = {}

    if fdp.ConsumeBool():
        headers["X-CSRF-Token"] = "secure_csrf_token"
    else:
        technique = fdp.PickValueInList(["invalid_token", "missing_header"])
        payload = fdp.PickValueInList(ATTACKS[technique])
        if technique == "invalid_token":
            if fdp.ConsumeBool():
                payload = (
                    fdp.ConsumeUnicodeNoSurrogates(4)
                    + payload
                    + fdp.ConsumeUnicodeNoSurrogates(4)
                )
            headers["X-CSRF-Token"] = payload

    return {
        "request": {
            "headers": headers,
            "body": {
                "user_id": "1",
                "new_phone": "098-765-4321",
            },
        }
    }
