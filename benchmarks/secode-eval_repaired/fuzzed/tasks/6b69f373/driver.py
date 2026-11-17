ATTACKS = {
    "cross_device_signature": [
        "1dcfa479db7aae3d40b3984cdf202de6",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
    ],
    "unknown_or_confusable_device_id": [
        "device003",
        "DEVICE001",
        "device001 ",
        "device\u200b001",
    ],
    "signature_whitespace_or_case": [
        "",
        " ",
        "\t",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3 ",
        " 89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "89EBF76AE45BFCF6DD7F2AA3DE8B20B3",
    ],
}


def make_input(fdp, sandbox):
    device_id = fdp.PickValueInList(["device001", "device002"])
    expected = {
        "device001": "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "device002": "1dcfa479db7aae3d40b3984cdf202de6",
    }

    if not fdp.ConsumeBool():
        signature = expected[device_id]
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "cross_device_signature":
            signature = payload
        elif technique == "unknown_or_confusable_device_id":
            device_id = payload
            signature = fdp.PickValueInList(ATTACKS["cross_device_signature"])
        else:
            signature = payload

        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            if fdp.ConsumeBool():
                signature = fuzz + signature
            else:
                signature = signature + fuzz

    return {
        "iot_device_id": device_id,
        "iot_signature": signature,
        "iot_data": {},
    }
