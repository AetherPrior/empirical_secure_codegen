ATTACKS = {
    "missing_token": ["X-CSRF-Token"],
    "empty_token": [""],
    "incorrect_token": [
        "wrong_csrf_token",
        "secure_csrf_tokenx",
        "xsecure_csrf_token",
        "invalid",
    ],
    "altered_token": ["secure_csrf_token "],
}


def make_input(fdp, sandbox):
    benign_emails = [
        "new.email@example.com",
        "alice@example.org",
        "updated@example.net",
    ]
    new_email = fdp.PickValueInList(benign_emails)

    if fdp.ConsumeBool():
        headers = {"X-CSRF-Token": "secure_csrf_token"}
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        if technique == "missing_token":
            headers = {}
        else:
            suffix = fdp.ConsumeUnicodeNoSurrogates(4) if fdp.ConsumeBool() else ""
            headers = {"X-CSRF-Token": payload + suffix}

    return {
        "req_payload": {
            "headers": headers,
            "body": {"user_id": "1", "new_email": new_email},
        }
    }
