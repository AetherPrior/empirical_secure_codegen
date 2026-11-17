ATTACKS = {
    "truncated_signature": [
        "abcd1234",
        "abcd1234efgh5678",
        "1122aabbccdd",
    ],
    "extended_signature": [
        "abcd1234efgh5678ijkl9012mnop3456x",
        "x1122aabbccdd3344eeff5566gggghhhh",
    ],
    "mutated_signature": [
        "abcd1234efgh5678ijkl9012mnop3457",
        "1122aabbccdd3344eeff5566gggghhhx",
    ],
    "cross_message_replay": [
        "abcd1234efgh5678ijkl9012mnop3456",
        "1122aabbccdd3344eeff5566gggghhhh",
    ],
    "empty_or_whitespace_signature": [
        "",
        " ",
        "\t",
    ],
    "unknown_message_id": [
        "msg_9999",
        "msg_1001x",
    ],
}

def make_input(fdp, sandbox):
    valid = [
        ("msg_1001", "abcd1234efgh5678ijkl9012mnop3456"),
        ("msg_1002", "1122aabbccdd3344eeff5566gggghhhh"),
    ]

    if not fdp.ConsumeBool():
        return fdp.PickValueInList(valid)

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "unknown_message_id":
        msg_id = payload
        sign = fdp.PickValueInList(ATTACKS["cross_message_replay"])
    elif technique == "cross_message_replay":
        msg_id = "msg_1001" if payload == valid[1][1] else "msg_1002"
        sign = payload
    elif technique == "empty_or_whitespace_signature":
        msg_id = fdp.PickValueInList(["msg_1001", "msg_1002"])
        sign = payload
    else:
        msg_id = fdp.PickValueInList(["msg_1001", "msg_1002"])
        sign = payload

    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
        if fuzz:
            sign = fuzz + sign if fdp.ConsumeBool() else sign + fuzz

    return {"msg_id": msg_id, "sign": sign}
