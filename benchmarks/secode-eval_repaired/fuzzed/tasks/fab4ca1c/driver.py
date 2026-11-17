ATTACKS = {
    "single_character_change": [
        "abcd5678efgh1234ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3457",
    ],
    "truncation": [
        "abcd1234efgh5678ijkl9012mnop345",
        "abcd1234efgh5678",
        "",
    ],
    "extra_characters": [
        "abcd1234efgh5678ijkl9012mnop3456x",
        "xabcd1234efgh5678ijkl9012mnop3456",
    ],
    "whitespace": [
        " abcd1234efgh5678ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3456\n",
    ],
    "case_change": [
        "ABCD1234EFGH5678IJKL9012MNOP3456",
    ],
    "unknown_identifier": [
        "",
        "msg_9999",
        "msg_1001x",
        "MSG_1001",
    ],
    "cross_message_signature": [
        "1122aabbccdd3344eeff5566gggghhhh",
    ],
}


def make_input(fdp, sandbox):
    valid = [
        {
            "msg_identifier": "msg_1001",
            "sign": "abcd1234efgh5678ijkl9012mnop3456",
        },
        {
            "msg_identifier": "msg_1002",
            "sign": "1122aabbccdd3344eeff5566gggghhhh",
        },
    ]

    if not fdp.ConsumeBool():
        return fdp.PickValueInList(valid)

    mode = fdp.ConsumeIntInRange(0, 3)
    if mode == 0:
        families = [
            "single_character_change",
            "truncation",
            "extra_characters",
            "whitespace",
            "case_change",
        ]
        family = fdp.PickValueInList(families)
        return {
            "msg_identifier": "msg_1001",
            "sign": fdp.PickValueInList(ATTACKS[family]),
        }

    if mode == 1:
        return {
            "msg_identifier": fdp.PickValueInList(
                ATTACKS["unknown_identifier"]
            ),
            "sign": fdp.PickValueInList(
                [
                    "abcd1234efgh5678ijkl9012mnop3456",
                    "1122aabbccdd3344eeff5566gggghhhh",
                ]
            ),
        }

    if mode == 2:
        return {
            "msg_identifier": "msg_1001",
            "sign": fdp.PickValueInList(
                ATTACKS["cross_message_signature"]
            ),
        }

    family = fdp.PickValueInList(
        ["single_character_change", "extra_characters", "whitespace"]
    )
    payload = fdp.PickValueInList(ATTACKS[family])
    fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
    return {
        "msg_identifier": "msg_1001",
        "sign": payload + fuzz,
    }
