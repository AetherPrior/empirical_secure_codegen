ATTACKS = {
    "substring": ["abcd", "efgh5678", "mnop3456"],
    "prefix_match": [
        "abcd1234efgh5678ijkl9012mnop3456.extra",
    ],
    "suffix_match": [
        "extra.abcd1234efgh5678ijkl9012mnop3456",
    ],
    "near_match": [
        "abcd5678efgh1234ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop345X",
    ],
    "case_or_whitespace": [
        "ABCD1234EFGH5678IJKL9012MNOP3456",
        " abcd1234efgh5678ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3456 ",
    ],
    "empty_signature": [""],
    "cross_message_replay": ["1122aabbccdd3344eeff5566gggghhhh"],
    "unknown_message_id": ["msg_unknown"],
}


def make_input(fdp, sandbox):
    valid = {
        "msg_1001": "abcd1234efgh5678ijkl9012mnop3456",
        "msg_1002": "1122aabbccdd3344eeff5566gggghhhh",
    }

    if not fdp.ConsumeBool():
        msg_id = fdp.PickValueInList(sorted(valid))
        return {"msg_id": msg_id, "sig": valid[msg_id]}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "unknown_message_id":
        msg_id = payload
        sig = valid["msg_1001"]
    else:
        msg_id = "msg_1001"
        sig = payload

    if fdp.ConsumeBool() and technique != "unknown_message_id":
        noise = fdp.ConsumeUnicodeNoSurrogates(3)
        if noise:
            sig = noise + sig if fdp.ConsumeBool() else sig + noise

    return {"msg_id": msg_id, "sig": sig}
