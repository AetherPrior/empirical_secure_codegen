ATTACKS = {
    "missing_token": ["<absent>"],
    "forged_token": ["invalid", "not-a-token", "secure_csrf_tokenx"],
    "token_whitespace": [" secure_csrf_token", "secure_csrf_token "],
    "token_case_mismatch": ["SECURE_CSRF_TOKEN"],
    "header_name_confusion": ["x-csrf-token", "X_CSRF_Token", "X-XSRF-TOKEN"],
}


def make_input(fdp, sandbox):
    headers = {}

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "missing_token":
            pass
        elif technique == "header_name_confusion":
            headers[payload] = "secure_csrf_token"
        else:
            prefix = fdp.ConsumeUnicodeNoSurrogates(3)
            suffix = fdp.ConsumeUnicodeNoSurrogates(3)
            headers["X-CSRF-Token"] = prefix + payload + suffix
    else:
        headers["X-CSRF-Token"] = "secure_csrf_token"

    email = fdp.PickValueInList([
        "new.email@example.com",
        "user@example.org",
    ])

    return {
        "new_request": {
            "headers": headers,
            "body": {
                "user_id": "1",
                "new_email": email,
            },
        }
    }
