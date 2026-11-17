ATTACKS = {
    "truncated_signature": [
        "abcd1234",
        "abcd1234efgh5678ijkl9012mnop",
    ],
    "extended_signature": [
        "abcd1234efgh5678ijkl9012mnop3456x",
        "xabcd1234efgh5678ijkl9012mnop3456",
    ],
    "signature_formatting": [
        " abcd1234efgh5678ijkl9012mnop3456",
        "abcd1234efgh5678ijkl9012mnop3456 ",
        "ABCD1234EFGH5678IJKL9012MNOP3456",
    ],
    "replayed_signature": [
        "1122aabbccdd3344eeff5566gggghhhh",
    ],
    "identifier_confusion": [
        "msg_1002",
        "msg_1001x",
        "unknown",
    ],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        message_id = fdp.PickValueInList(["msg_1001", "msg_1002"])
        signature = (
            "abcd1234efgh5678ijkl9012mnop3456"
            if message_id == "msg_1001"
            else "1122aabbccdd3344eeff5566gggghhhh"
        )
        return {
            "api_message_id": message_id,
            "crypto_signature": signature,
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "identifier_confusion":
        message_id = payload
        signature = "abcd1234efgh5678ijkl9012mnop3456"
    elif technique == "replayed_signature":
        message_id = "msg_1001"
        signature = payload
    else:
        message_id = "msg_1001"
        signature = payload

    if fdp.ConsumeBool():
        fuzz_text = fdp.ConsumeUnicodeNoSurrogates(3)
        if fdp.ConsumeBool():
            signature = fuzz_text + signature
        else:
            signature = signature + fuzz_text

    return {
        "api_message_id": message_id,
        "crypto_signature": signature,
    }
