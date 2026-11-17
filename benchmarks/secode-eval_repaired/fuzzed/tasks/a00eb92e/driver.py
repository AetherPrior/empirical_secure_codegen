ATTACKS = {
    "near_match": [
        "abcd5678efgh1234ijkl9012mnop3456",
        "1122aabbccdd3344eeff5566gggghhhX",
    ],
    "truncated_signature": [
        "abcd1234efgh5678",
        "1122aabbccdd3344",
    ],
    "extended_signature": [
        "abcd1234efgh5678ijkl9012mnop3456x",
        "1122aabbccdd3344eeff5566gggghhhh=",
    ],
    "altered_format": [
        "ABCD1234EFGH5678IJKL9012MNOP3456",
        " abcd1234efgh5678ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3456\n",
    ],
    "signature_for_other_message": [
        "abcd1234efgh5678ijkl9012mnop3456",
        "1122aabbccdd3344eeff5566gggghhhh",
    ],
    "unknown_identifier": [
        "msg_9999",
        "msg_1001x",
        "",
    ],
    "empty_signature": [
        "",
        " ",
        "\x00",
    ],
}


def make_input(fdp, sandbox):
    valid = {
        "msg_1001": "abcd1234efgh5678ijkl9012mnop3456",
        "msg_1002": "1122aabbccdd3344eeff5566gggghhhh",
    }
    identifiers = list(valid)

    if not fdp.ConsumeBool():
        identifier = fdp.PickValueInList(identifiers)
        return {
            "msg_identifier": identifier,
            "crypto_sign": valid[identifier],
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "unknown_identifier":
        return {
            "msg_identifier": payload,
            "crypto_sign": fdp.PickValueInList(list(valid.values())),
        }

    if technique == "signature_for_other_message":
        identifier = fdp.PickValueInList(identifiers)
        other_identifier = "msg_1002" if identifier == "msg_1001" else "msg_1001"
        return {
            "msg_identifier": identifier,
            "crypto_sign": valid[other_identifier],
        }

    identifier = fdp.PickValueInList(identifiers)
    if technique == "empty_signature":
        return {"msg_identifier": identifier, "crypto_sign": payload}

    return {"msg_identifier": identifier, "crypto_sign": payload}
