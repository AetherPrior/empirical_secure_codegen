ATTACKS = {
    "cross_device_signature": ["1dcfa479db7aae3d40b3984cdf202de6"],
    "mutated_signature": [
        "89ebf76ae45bfcf6dd7f2aa3de8b20b0",
        "89ebf76ae45bfcf6dd7f2aa3de8b20",
    ],
    "empty_signature": [""],
    "signature_format": [
        "89EBF76AE45BFCF6DD7F2AA3DE8B20B3",
        " 89ebf76ae45bfcf6dd7f2aa3de8b20b3",
    ],
    "device_id_confusion": ["device001 ", " device001"],
    "unknown_device": ["device999"],
}


def make_input(fdp, sandbox):
    benign_devices = [
        ("device001", "89ebf76ae45bfcf6dd7f2aa3de8b20b3"),
        ("device002", "1dcfa479db7aae3d40b3984cdf202de6"),
    ]

    if fdp.ConsumeBool():
        device_id, crypt_sig = fdp.PickValueInList(benign_devices)
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "cross_device_signature":
            device_id, crypt_sig = "device001", payload
        elif technique == "mutated_signature":
            device_id, crypt_sig = "device001", payload
        elif technique == "empty_signature":
            device_id, crypt_sig = "device001", payload
        elif technique == "signature_format":
            device_id, crypt_sig = "device001", payload
        elif technique == "device_id_confusion":
            device_id, crypt_sig = payload, "89ebf76ae45bfcf6dd7f2aa3de8b20b3"
        else:
            device_id, crypt_sig = payload, "89ebf76ae45bfcf6dd7f2aa3de8b20b3"

        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            if fdp.ConsumeBool():
                crypt_sig = fuzz + crypt_sig
            else:
                crypt_sig = crypt_sig + fuzz

    pkt_data = {
        "temperature": fdp.ConsumeIntInRange(-10, 60),
        "humidity": fdp.ConsumeIntInRange(0, 100),
    }
    return {
        "device_id": device_id,
        "crypt_sig": crypt_sig,
        "pkt_data": pkt_data,
    }
