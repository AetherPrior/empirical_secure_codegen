ATTACKS = {
    "missing_token": [""],
    "wrong_token": [
        "invalid_csrf_token",
        "attacker_controlled_token",
        "not-the-token",
    ],
    "token_boundary_mutation": [
        "xsecure_csrf_token",
        "secure_csrf_tokenx",
    ],
    "token_whitespace": [
        " secure_csrf_token",
        "secure_csrf_token ",
        "\tsecure_csrf_token",
    ],
    "token_case_mutation": [
        "SECURE_CSRF_TOKEN",
        "Secure_Csrf_Token",
    ],
    "combined_tokens": [
        "secure_csrf_token, attacker_controlled_token",
        "attacker_controlled_token, secure_csrf_token",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        headers = {"X-CSRF-Token": "secure_csrf_token"}
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "missing_token":
            headers = {}
        else:
            if fdp.ConsumeBool():
                payload = fdp.ConsumeUnicodeNoSurrogates(4) + payload
            if fdp.ConsumeBool():
                payload = payload + fdp.ConsumeUnicodeNoSurrogates(4)
            headers = {"X-CSRF-Token": payload}

    return {
        "req": {
            "headers": headers,
            "body": {
                "user_id": "1",
                "new_email": "new.email@example.com",
            },
        }
    }
