ATTACKS = {
    "missing_token": [""],
    "invalid_token": [
        "invalid",
        "secure_csrf_tokenx",
        " secure_csrf_token",
        "secure_csrf_token ",
    ],
    "header_name_confusion": [
        "x-csrf-token",
        "X_CSRF_Token",
        "CSRF-Token",
    ],
    "body_only_token": ["secure_csrf_token"],
}


def make_input(fdp, sandbox):
    headers = {}
    body = {
        "user_id": "1",
        "new_phone": fdp.PickValueInList(
            ["098-765-4321", "555-0100", "212-555-0199"]
        ),
    }

    if fdp.ConsumeBool():
        headers["X-CSRF-Token"] = "secure_csrf_token"
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "missing_token":
            pass
        elif technique == "invalid_token":
            headers["X-CSRF-Token"] = payload
        elif technique == "header_name_confusion":
            headers[payload] = "secure_csrf_token"
        elif technique == "body_only_token":
            body["csrf_token"] = payload

    return {"user_request": {"headers": headers, "body": body}}
