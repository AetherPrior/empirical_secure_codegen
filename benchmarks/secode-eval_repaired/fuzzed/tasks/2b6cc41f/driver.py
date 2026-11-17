ATTACKS = {
    "missing_token": ["<absent>"],
    "invalid_token": [
        "",
        "wrong_csrf_token",
        "secure_csrf_token ",
        " secure_csrf_token",
        "secure_csrf_tokenx",
    ],
    "header_name_confusion": [
        "x-csrf-token",
        "X-Csrf-Token",
        "X-CSRF-TOKEN",
    ],
    "body_token_only": ["csrf_token"],
}


def make_input(fdp, sandbox):
    expected = "secure_csrf_token"
    headers = {}
    body = {
        "user_id": "1",
        "new_email": "new.email@example.com",
    }

    if fdp.ConsumeBool():
        headers["X-CSRF-Token"] = expected
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "invalid_token":
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            token = payload
            if fdp.ConsumeBool():
                token = fuzz + token
            elif fuzz:
                token = token + fuzz
            headers["X-CSRF-Token"] = token
        elif technique == "header_name_confusion":
            headers[payload] = expected
        elif technique == "body_token_only":
            body[payload] = expected
        # missing_token deliberately leaves the headers mapping empty

    return {"req_data": {"headers": headers, "body": body}}
