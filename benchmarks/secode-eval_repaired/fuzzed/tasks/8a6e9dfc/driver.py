ATTACKS = {
    "missing_token": ["<MISSING>"],
    "empty_token": [""],
    "incorrect_token": ["invalid", "not_the_csrf_token"],
    "modified_valid_token": [
        "secure_csrf_tokenx",
        "xsecure_csrf_token",
        "secure_csrf_token ",
    ],
    "case_changed_token": ["Secure_CSRF_Token", "SECURE_CSRF_TOKEN"],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        token = fdp.PickValueInList(ATTACKS[technique])
        headers = {}

        if token != "<MISSING>":
            if technique in ("incorrect_token", "modified_valid_token") and fdp.ConsumeBool():
                fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
                token = fuzz + token + fdp.ConsumeUnicodeNoSurrogates(4)
            headers["X-CSRF-Token"] = token
    else:
        headers = {"X-CSRF-Token": "secure_csrf_token"}

    return {
        "payload": {
            "headers": headers,
            "body": {
                "user_id": "1",
                "new_email": "new.email@example.com",
            },
        }
    }
