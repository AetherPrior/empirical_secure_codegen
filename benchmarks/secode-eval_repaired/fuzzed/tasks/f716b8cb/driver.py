ATTACKS = {
    "missing_token": [""],
    "incorrect_token": [
        "invalid_csrf_token",
        "secure_csrf_tokenx",
        "xsecure_csrf_token",
    ],
    "whitespace_token": [
        " secure_csrf_token",
        "secure_csrf_token ",
    ],
    "alternate_header": [
        "x-csrf-token",
        "X_CSRF_Token",
        "X-CSRF-Token ",
    ],
    "body_only_token": ["secure_csrf_token"],
}


def make_input(fdp, sandbox):
    user_id = "1"
    new_email = "new.email@example.com"

    if not fdp.ConsumeBool():
        headers = {"X-CSRF-Token": "secure_csrf_token"}
        body = {"user_id": user_id, "new_email": new_email}
        return {"user_request": {"headers": headers, "body": body}}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    headers = {}
    body = {"user_id": user_id, "new_email": new_email}

    if technique == "incorrect_token" or technique == "whitespace_token":
        if fdp.ConsumeBool():
            payload = fdp.ConsumeUnicodeNoSurrogates(4) + payload
        headers["X-CSRF-Token"] = payload
    elif technique == "alternate_header":
        headers[payload] = fdp.PickValueInList(ATTACKS["incorrect_token"])
    elif technique == "body_only_token":
        body["csrf_token"] = payload
    # missing_token intentionally leaves the headers empty.

    return {"user_request": {"headers": headers, "body": body}}
