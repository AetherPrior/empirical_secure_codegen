ATTACKS = {
    "signature_substitution": [
        "abcd5678efgh1234ijkl9012mnop3456",
        "1122aabbccdd3344eeff5566gggghhhh",
    ],
    "whitespace": [
        " abcd1234efgh5678ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3456 ",
    ],
    "case_change": [
        "ABCD1234EFGH5678IJKL9012MNOP3456",
    ],
    "truncation": [
        "",
        "abcd1234efgh5678",
    ],
    "prefix_suffix": [
        "x" + "abcd1234efgh5678ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3456x",
    ],
    "unknown_message": [
        "msg_9999",
        "",
    ],
}


def make_input(fdp, sandbox):
    valid = {
        "msg_1001": "abcd1234efgh5678ijkl9012mnop3456",
        "msg_1002": "1122aabbccdd3344eeff5566gggghhhh",
    }

    if not fdp.ConsumeBool():
        msg_code = fdp.PickValueInList(list(valid))
        return {"msg_code": msg_code, "crypto_sign": valid[msg_code]}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "unknown_message":
        msg_code = payload
        crypto_sign = fdp.PickValueInList(list(valid.values()))
    else:
        msg_code = fdp.PickValueInList(list(valid))
        crypto_sign = payload
        if fdp.ConsumeBool():
            crypto_sign = (
                fdp.ConsumeUnicodeNoSurrogates(3)
                + crypto_sign
                + fdp.ConsumeUnicodeNoSurrogates(3)
            )

    return {"msg_code": msg_code, "crypto_sign": crypto_sign}
