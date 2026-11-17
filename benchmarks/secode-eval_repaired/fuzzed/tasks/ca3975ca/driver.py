ATTACKS = {
    "empty_or_wrong_token": ["", "invalid", "null", "undefined"],
    "token_mutation": [
        "secure_csrf_token_valuex",
        "xsecure_csrf_token_value",
        "secure_csrf_token_value ",
        "secure_csrf_token_value\x00",
        "secure_csrf_token_value, secure_csrf_token_value",
    ],
    "header_name_confusion": [
        "x-csrf-token",
        "X-CSRF-TOKEN",
        "X-CSRF-Token ",
    ],
}


def make_input(fdp, sandbox):
    mode = fdp.ConsumeIntInRange(0, 5)
    headers = {}

    if mode in (0, 1):
        # Benign request with the exact expected token.
        headers["X-CSRF-Token"] = "secure_csrf_token_value"
    elif mode == 2:
        # Missing token.
        pass
    elif mode == 3:
        family = fdp.PickValueInList(
            ["empty_or_wrong_token", "token_mutation"]
        )
        token = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(3)
            suffix = fdp.ConsumeUnicodeNoSurrogates(3)
            token = prefix + token + suffix
        headers["X-CSRF-Token"] = token
    elif mode == 4:
        key = fdp.PickValueInList(ATTACKS["header_name_confusion"])
        headers[key] = "secure_csrf_token_value"
    else:
        # Wrong token under the expected header name.
        token = fdp.PickValueInList(ATTACKS["empty_or_wrong_token"])
        headers["X-CSRF-Token"] = token

    return {
        "request_data": {
            "headers": headers,
            "body": {
                "user_id": "1",
                "new_phone": "098-765-4321",
            },
        }
    }
