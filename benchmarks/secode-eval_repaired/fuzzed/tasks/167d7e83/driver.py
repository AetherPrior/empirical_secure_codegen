ATTACKS = {
    "missing_header": ["<missing>"],
    "empty_header": [""],
    "invalid_token": [
        "invalid_csrf_token",
        "secure_csrf_tokenx",
        "secure_csrf_token ",
    ],
    "body_token_only": [
        "invalid_csrf_token",
        "secure_csrf_tokenx",
    ],
}


def make_input(fdp, sandbox):
    request = {
        "headers": {},
        "body": {
            "user_id": "1",
            "new_email": "new.email@example.com",
        },
    }

    if fdp.ConsumeBool():
        request["headers"]["X-CSRF-Token"] = "secure_csrf_token"
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "missing_header":
            pass
        elif technique == "body_token_only":
            request["body"]["csrf_token"] = payload + fdp.ConsumeUnicodeNoSurrogates(3)
        else:
            request["headers"]["X-CSRF-Token"] = (
                payload + fdp.ConsumeUnicodeNoSurrogates(3)
            )

    return {"request": request}
