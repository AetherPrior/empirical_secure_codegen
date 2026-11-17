ATTACKS = {
    "forged_token": [
        "invalid",
        "forged_csrf_token",
        "null",
        "undefined",
        "secure_csrf_tokenx",
    ],
    "token_format_confusion": [
        " secure_csrf_token",
        "secure_csrf_token ",
        "Bearer secure_csrf_token",
        "secure_csrf_token, forged",
    ],
    "header_name_confusion": [
        "csrf-token",
        "X-CSRF-TOKEN",
        "x-csrf-token",
        "X_CSRF_Token",
    ],
}


def make_input(fdp, sandbox):
    headers = {}
    body = {
        "user_id": "1",
        "new_phone": "098-765-4321" if fdp.ConsumeBool() else "111-222-3333",
    }

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])

        if family == "header_name_confusion":
            headers[payload] = fdp.PickValueInList(ATTACKS["forged_token"])
        else:
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            headers["X-CSRF-Token"] = payload + fuzz

        if fdp.ConsumeBool():
            body["csrf_token"] = fdp.PickValueInList(ATTACKS["forged_token"])
    elif fdp.ConsumeBool():
        headers["X-CSRF-Token"] = "secure_csrf_token"

    return {"request_details": {"headers": headers, "body": body}}
