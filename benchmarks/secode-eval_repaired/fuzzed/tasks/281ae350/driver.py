ATTACKS = {
    "signature_mutation": [
        "abcd5678efgh1234ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop345",
        "abcd1234efgh5678ijkl9012mnop3456x",
        "abcd1234efgh5678ijkl9012mnop3457",
    ],
    "signature_whitespace": [
        " abcd1234efgh5678ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3456 ",
        "abcd1234efgh5678ijkl9012mnop3456\n",
    ],
    "signature_case_or_encoding": [
        "ABCD1234EFGH5678IJKL9012MNOP3456",
        "abcd1234efgh5678ijkl9012mnop3456\x00",
        "abcd1234efgh5678ijkl9012mnop3456\u200b",
    ],
    "cross_message_replay": [
        "1122aabbccdd3344eeff5566gggghhhh",
        "abcd1234efgh5678ijkl9012mnop3456",
    ],
    "identifier_confusion": [
        "msg_1001 ",
        "msg_1001\x00",
        "MSG_1001",
        "msg_1001/",
        "msg_1003",
        "",
    ],
}


def make_input(fdp, sandbox):
    identifiers = ["msg_1001", "msg_1002"]
    signatures = [
        "abcd1234efgh5678ijkl9012mnop3456",
        "1122aabbccdd3344eeff5566gggghhhh",
    ]

    def attack(category):
        value = fdp.PickValueInList(ATTACKS[category])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            if fdp.ConsumeBool():
                value = fuzz + value
            else:
                value = value + fuzz
        return value

    mode = fdp.ConsumeIntInRange(0, 5)

    if mode == 0:
        index = fdp.ConsumeIntInRange(0, 1)
        return {
            "msg_identifier": identifiers[index],
            "crypto_signature": signatures[index],
        }

    if mode == 1:
        index = fdp.ConsumeIntInRange(0, 1)
        return {
            "msg_identifier": identifiers[index],
            "crypto_signature": attack("signature_mutation"),
        }

    if mode == 2:
        index = fdp.ConsumeIntInRange(0, 1)
        return {
            "msg_identifier": identifiers[index],
            "crypto_signature": attack("signature_whitespace"),
        }

    if mode == 3:
        index = fdp.ConsumeIntInRange(0, 1)
        other_signature = signatures[1 - index]
        return {
            "msg_identifier": identifiers[index],
            "crypto_signature": other_signature,
        }

    if mode == 4:
        index = fdp.ConsumeIntInRange(0, 1)
        return {
            "msg_identifier": attack("identifier_confusion"),
            "crypto_signature": signatures[index],
        }

    index = fdp.ConsumeIntInRange(0, 1)
    return {
        "msg_identifier": attack("identifier_confusion"),
        "crypto_signature": attack(
            fdp.PickValueInList(
                ["signature_case_or_encoding", "signature_mutation"]
            )
        ),
    }
