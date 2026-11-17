ATTACKS = {
    "tampered_signature": [
        "abcd5678efgh1234ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3457",
    ],
    "truncated_or_extended_signature": [
        "abcd1234",
        "abcd1234efgh5678ijkl9012mnop3456x",
    ],
    "case_changed_signature": [
        "ABCD1234EFGH5678IJKL9012MNOP3456",
    ],
    "whitespace_changed_signature": [
        " abcd1234efgh5678ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3456 ",
    ],
    "unknown_or_near_match_message": [
        "msg_9999",
        "msg_1001x",
        "msg_100",
    ],
    "cross_message_signature": [
        "1122aabbccdd3344eeff5566gggghhhh",
    ],
}

def make_input(fdp, sandbox):
    valid = {
        "msg_1001": "abcd1234efgh5678ijkl9012mnop3456",
        "msg_1002": "1122aabbccdd3344eeff5566gggghhhh",
    }

    if not fdp.ConsumeBool():
        message = fdp.PickValueInList(list(valid))
        return {"api_message": message, "sig": valid[message]}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "unknown_or_near_match_message":
        message = payload
        sig = valid["msg_1001"]
    elif technique == "cross_message_signature":
        message = "msg_1001"
        sig = payload
    else:
        message = fdp.PickValueInList(list(valid))
        sig = payload

    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
        if fdp.ConsumeBool():
            sig = fuzz + sig
        else:
            sig = sig + fuzz

    return {"api_message": message, "sig": sig}
