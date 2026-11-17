ATTACKS = {
    "missing_header": ["<missing>"],
    "empty_token": [""],
    "forged_token": ["invalid_csrf_token", "attacker_token"],
    "token_mutation": ["secure_csrf_tokenx", "secure_csrf_token "],
    "wrong_case": ["SECURE_CSRF_TOKEN"],
    "body_only_token": ["secure_csrf_token"],
}


def make_input(fdp, sandbox):
    body = {
        "user_id": "1",
        "new_email": "new.email@example.com",
    }

    if not fdp.ConsumeBool():
        headers = {"X-CSRF-Token": "secure_csrf_token"}
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        headers = {}
        if technique == "body_only_token":
            body["csrf_token"] = payload
        elif technique != "missing_header":
            headers["X-CSRF-Token"] = payload

    return {"request_data": {"headers": headers, "body": body}}
