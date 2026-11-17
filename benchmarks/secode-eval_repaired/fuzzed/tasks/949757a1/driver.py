ATTACKS = {
    "missing_header": [""],
    "invalid_token": ["", "invalid", "secure_csrf_token ", "secure_csrf_tokenx"],
    "alternate_header": ["X-XSRF-Token", "CSRF-Token", "X-CSRFToken"],
}


def make_input(fdp, sandbox):
    user_id = "1"
    new_phone = "098-765-4321"

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "missing_header":
            headers = {}
        elif technique == "alternate_header":
            bad_token = fdp.PickValueInList(ATTACKS["invalid_token"])
            headers = {payload: bad_token}
        else:
            headers = {"X-CSRF-Token": payload}
    else:
        headers = {"X-CSRF-Token": "secure_csrf_token"}
        new_phone = fdp.PickValueInList(
            ["098-765-4321", "555-0100", "212-555-0199"]
        )

    return {
        "transaction_request": {
            "headers": headers,
            "body": {"user_id": user_id, "new_phone": new_phone},
        }
    }
