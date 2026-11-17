ATTACKS = {
    "cross_device_replay": [
        "1dcfa479db7aae3d40b3984cdf202de6",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
    ],
    "signature_whitespace": [
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3 ",
        " 1dcfa479db7aae3d40b3984cdf202de6",
    ],
    "signature_case_change": [
        "89EBF76AE45BFCF6DD7F2AA3DE8B20B3",
        "1DCFA479DB7AAE3D40B3984CDF202DE6",
    ],
    "truncated_signature": [
        "89ebf76ae45bfcf6",
        "1dcfa479db7aae3d",
    ],
}


def make_input(fdp, sandbox):
    device_index = fdp.ConsumeIntInRange(0, 1)
    dev_id = ("device001", "device002")[device_index]

    if fdp.ConsumeBool():
        # A valid signature for the other device must not authenticate this one.
        crypto_sign = ATTACKS["cross_device_replay"][device_index]
    else:
        family = fdp.PickValueInList(
            ["signature_whitespace", "signature_case_change", "truncated_signature"]
        )
        crypto_sign = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            crypto_sign = (
                fdp.ConsumeUnicodeNoSurrogates(3)
                + crypto_sign
                + fdp.ConsumeUnicodeNoSurrogates(3)
            )

    if fdp.ConsumeBool():
        # Benign signatures are kept as ordinary samples, not attack payloads.
        crypto_sign = (
            "89ebf76ae45bfcf6dd7f2aa3de8b20b3"
            if device_index == 0
            else "1dcfa479db7aae3d40b3984cdf202de6"
        )

    packet_content = {}
    if fdp.ConsumeBool():
        packet_content[fdp.ConsumeUnicodeNoSurrogates(8)] = (
            fdp.ConsumeUnicodeNoSurrogates(8)
        )

    return {
        "dev_id": dev_id,
        "crypto_sign": crypto_sign,
        "packet_content": packet_content,
    }
