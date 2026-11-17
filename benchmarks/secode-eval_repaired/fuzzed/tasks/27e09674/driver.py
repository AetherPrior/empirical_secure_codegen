ATTACKS = {
    "wrong_token": [
        "not-a-token",
        "invalid",
        "wrong",
    ],
    "token_prefix_suffix": [
        "xsecure_csrf_token",
        "secure_csrf_tokenx",
        "secure_csrf_token ",
        " secure_csrf_token",
    ],
    "token_case_change": [
        "Secure_csrf_token",
        "SECURE_CSRF_TOKEN",
    ],
    "header_injection": [
        "secure_csrf_token\r\nX-CSRF-Token: secure_csrf_token",
    ],
}


def make_input(fdp, sandbox):
    headers = {}

    if fdp.ConsumeBool():
        # Benign request with the exact expected token.
        headers["X-CSRF-Token"] = "secure_csrf_token"
    elif fdp.ConsumeBool():
        # Missing token.
        pass
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        headers["X-CSRF-Token"] = prefix + payload + suffix

    return {
        "query": {
            "headers": headers,
            "body": {
                "user_id": "1",
                "new_email": "new.email@example.com",
            },
        }
    }
