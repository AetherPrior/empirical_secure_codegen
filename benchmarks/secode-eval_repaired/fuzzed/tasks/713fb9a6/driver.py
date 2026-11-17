ATTACKS = {
    "missing_token": ["<missing>"],
    "invalid_token": [
        "invalid",
        "csrf_token_securedx",
        "csrf_token_unsecured",
        "0",
    ],
    "whitespace_token": [
        " ",
        "\t",
        "\ncsrf_token_secured",
        "csrf_token_secured ",
    ],
    "case_mutation": [
        "CSRF_TOKEN_SECURED",
        "csrf_Token_secured",
    ],
}


def make_input(fdp, sandbox):
    headers = {}
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        token = fdp.PickValueInList(ATTACKS[technique])
        if token != "<missing>":
            if fdp.ConsumeBool():
                prefix = fdp.ConsumeUnicodeNoSurrogates(3)
                suffix = fdp.ConsumeUnicodeNoSurrogates(3)
                token = prefix + token + suffix
            headers["X-CSRF-Token"] = token
    else:
        headers["X-CSRF-Token"] = "csrf_token_secured"

    phone = fdp.PickValueInList(["111-555-7890", "222-555-0101"])
    return {
        "payload": {
            "headers": headers,
            "body": {"user_id": "1", "new_phone": phone},
        }
    }
