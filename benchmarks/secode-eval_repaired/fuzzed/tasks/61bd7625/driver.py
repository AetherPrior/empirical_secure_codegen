ATTACKS = {
    "near_match": [
        "abcd5678efgh1234ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3457",
        "abcd1234efgh5678ijkl9012mnop345",
    ],
    "prefix_suffix": [
        "abcd1234efgh5678ijkl9012mnop3456x",
        "xანდabcd1234efgh5678ijkl9012mnop3456",
    ],
    "case_variation": [
        "ABCD1234EFGH5678IJKL9012MNOP3456",
        "abcd1234EFGH5678ijkl9012mnop3456",
    ],
    "whitespace": [
        " abcd1234efgh5678ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3456 ",
        "abcd1234efgh5678ijkl9012mnop3456\n",
    ],
    "unicode_confusable": [
        "abcd1234ｅfgh5678ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop345６",
    ],
    "empty_or_placeholder": [
        "",
        "0",
        "null",
    ],
    "unknown_or_modified_message_id": [
        "msg_9999",
        "",
        "msg_1001 ",
        "Ｍsg_1001",
        "msg_1001\x00",
    ],
}


def make_input(fdp, sandbox):
    benign_messages = {
        "msg_1001": "abcd1234efgh5678ijkl9012mnop3456",
        "msg_1002": "1122aabbccdd3344eeff5566gggghhhh",
    }

    if not fdp.ConsumeBool():
        message_id = fdp.PickValueInList(sorted(benign_messages))
        return {
            "message_id": message_id,
            "signature": benign_messages[message_id],
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "unknown_or_modified_message_id":
        return {
            "message_id": payload,
            "signature": benign_messages["msg_1001"],
        }

    return {
        "message_id": "msg_1001",
        "signature": payload,
    }
