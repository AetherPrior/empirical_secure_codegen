ATTACKS = {
    "missing_token": [""],
    "invalid_token": [
        "invalid_csrf_token",
        "secure_csrf_tokenx",
        "SECURE_CSRF_TOKEN",
    ],
    "whitespace_token": [
        " secure_csrf_token",
        "secure_csrf_token ",
    ],
    "alternate_header": [
        "csrf-token",
        "x-csrf-token",
        "X-XSRF-TOKEN",
    ],
    "body_token_only": [
        "csrf_token",
        "csrfToken",
    ],
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
        piece = fdp.PickValueInList(ATTACKS[technique])

        if technique == "missing_token":
            headers = {"X-CSRF-Token": piece} if fdp.ConsumeBool() else {}
        elif technique in ("invalid_token", "whitespace_token"):
            headers = {"X-CSRF-Token": piece}
        elif technique == "alternate_header":
            headers = {piece: "secure_csrf_token"}
        else:
            headers = {}
            body[piece] = "secure_csrf_token"

    return {"payload": {"headers": headers, "body": body}}
