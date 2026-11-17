ATTACKS = {
    "cross_device_signature": [
        "1dcfa479db7aae3d40b3984cdf202de6",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
    ],
    "forged_signature": [
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
        "",
    ],
    "signature_format_confusion": [
        "89EBF76AE45BFCF6DD7F2AA3DE8B20B3",
        " 89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3 ",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b",
    ],
    "unknown_device": [
        "device999",
        "",
    ],
    "device_confusion": [
        "device002",
        "device001 ",
        " device001",
    ],
}


def make_input(fdp, sandbox):
    devices = [
        ("device001", "89ebf76ae45bfcf6dd7f2aa3de8b20b3"),
        ("device002", "1dcfa479db7aae3d40b3984cdf202de6"),
    ]

    if fdp.ConsumeBool():
        device, packet_signature = fdp.PickValueInList(devices)
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "cross_device_signature":
            device = "device001"
            packet_signature = payload
        elif technique == "unknown_device":
            device = payload
            packet_signature = "89ebf76ae45bfcf6dd7f2aa3de8b20b3"
        elif technique == "device_confusion":
            device = payload
            packet_signature = "89ebf76ae45bfcf6dd7f2aa3de8b20b3"
        else:
            device = "device001"
            packet_signature = payload

        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            if fdp.ConsumeBool():
                packet_signature = fuzz + packet_signature
            else:
                packet_signature = packet_signature + fuzz

    return {
        "device": device,
        "packet_signature": packet_signature,
        "data_packet": {},
    }
