ATTACKS = {
    "wrong_token": ["invalid_csrf_token", "known_csrf_tokenx", "0"],
    "whitespace_token": [" known_csrf_token", "known_csrf_token ", "\tknown_csrf_token"],
    "case_mutation": ["KNOWN_CSRF_TOKEN"],
    "wrong_header_name": ["csrf-token", "X-CSRF-TOKEN", "x-csrf-token"],
    "empty_token": [""],
}


def make_input(fdp, sandbox):
    mode = fdp.ConsumeIntInRange(0, 6)
    headers = {}

    if mode == 0:
        headers["X-CSRF-Token"] = "known_csrf_token"
    elif mode == 1:
        pass  # Missing token
    elif mode == 2:
        headers["X-CSRF-Token"] = fdp.PickValueInList(ATTACKS["wrong_token"])
    elif mode == 3:
        headers["X-CSRF-Token"] = fdp.PickValueInList(ATTACKS["whitespace_token"])
    elif mode == 4:
        headers["X-CSRF-Token"] = fdp.PickValueInList(ATTACKS["case_mutation"])
    elif mode == 5:
        name = fdp.PickValueInList(ATTACKS["wrong_header_name"])
        headers[name] = "known_csrf_token"
    else:
        headers["X-CSRF-Token"] = fdp.PickValueInList(ATTACKS["empty_token"])

    return {
        "input": {
            "headers": headers,
            "body": {
                "user_id": "1",
                "new_phone": "321-654-0987",
            },
        }
    }
