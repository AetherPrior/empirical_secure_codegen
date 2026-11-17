ATTACKS = {
    "absent_header": ["<absent>"],
    "empty_header": [""],
    "forged_token": [
        "invalid",
        "not_a_csrf_token",
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
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique != "absent_header":
            if fdp.ConsumeBool():
                payload = fdp.ConsumeUnicodeNoSurrogates(4) + payload
            if fdp.ConsumeBool():
                payload += fdp.ConsumeUnicodeNoSurrogates(4)
            headers["X-CSRF-Token"] = payload

    return {
        "incoming_request": {
            "headers": headers,
            "body": {
                "user_id": "1",
                "new_phone": "098-765-4321",
            },
        }
    }
