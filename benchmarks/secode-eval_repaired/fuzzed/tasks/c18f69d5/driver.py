ATTACKS = {
    "altered_signature": [
        "abcd5678efgh1234ijkl9012mnop3456",
        "1122aabbccdd3344eeff5566gggghhhx",
    ],
    "cross_message_replay": [
        "1122aabbccdd3344eeff5566gggghhhh",
        "abcd1234efgh5678ijkl9012mnop3456",
    ],
    "truncated_signature": [
        "abcd1234",
        "1122aabb",
    ],
    "extended_signature": [
        "abcd1234efgh5678ijkl9012mnop3456x",
        "1122aabbccdd3344eeff5566gggghhhh!",
    ],
    "whitespace_signature": [
        " abcd1234efgh5678ijkl9012mnop3456",
        "1122aabbccdd3344eeff5566gggghhhh ",
    ],
    "case_mutation": [
        "ABCD1234EFGH5678IJKL9012MNOP3456",
        "1122AABBCCDD3344EEFF5566GGGGHHHH",
    ],
    "empty_signature": [
        "",
        " ",
    ],
    "unknown_message_id": [
        "msg_1003",
        "unknown",
        "",
    ],
}


def make_input(fdp, sandbox):
    valid = {
        "msg_1001": "abcd1234efgh5678ijkl9012mnop3456",
        "msg_1002": "1122aabbccdd3344eeff5566gggghhhh",
    }

    if not fdp.ConsumeBool():
        message_id = fdp.PickValueInList(sorted(valid))
        return {
            "api_message_id": message_id,
            "cryptographic_sign": valid[message_id],
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "unknown_message_id":
        message_id = payload
        signature = fdp.PickValueInList(ATTACKS["cross_message_replay"])
    else:
        message_id = fdp.PickValueInList(sorted(valid))
        signature = payload

    if technique not in ("whitespace_signature", "empty_signature") and fdp.ConsumeBool():
        fuzz = fdp.ConsumeBytes(2).hex()
        if fdp.ConsumeBool():
            signature = fuzz + signature
        else:
            signature = signature + fuzz

    return {
        "api_message_id": message_id,
        "cryptographic_sign": signature,
    }
