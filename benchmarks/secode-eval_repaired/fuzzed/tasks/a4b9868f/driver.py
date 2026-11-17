ATTACKS = {
    "missing_token": ["<missing>"],
    "invalid_token": ["", "invalid", "secure_csrf_tokenx", "secure_csrf_token "],
    "whitespace_token": [" ", "\t", "\n"],
    "token_injection": ["secure_csrf_token,invalid", "Bearer secure_csrf_token"],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        headers = {"X-CSRF-Token": "secure_csrf_token"}
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        token = fdp.PickValueInList(ATTACKS[technique])
        if token == "<missing>":
            headers = {}
        else:
            if fdp.ConsumeBool():
                token = (
                    fdp.ConsumeUnicodeNoSurrogates(3)
                    + token
                    + fdp.ConsumeUnicodeNoSurrogates(3)
                )
            headers = {"X-CSRF-Token": token}

    return {
        "service_request": {
            "headers": headers,
            "body": {
                "user_id": "1",
                "new_phone": "098-765-4321",
            },
        }
    }
