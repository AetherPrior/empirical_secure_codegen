ATTACKS = {
    "cross_device_signature": [
        "1dcfa479db7aae3d40b3984cdf202de6",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
    ],
    "altered_signature": [
        "89ebf76ae45bfcf6dd7f2aa3de8b20b",
        "1dcfa479db7aae3d40b3984cdf202de",
        "89EBF76AE45BFCF6DD7F2AA3DE8B20B3",
        "1dcfa479db7aae3d40b3984cdf202de6 ",
    ],
    "empty_or_garbage_signature": ["", "unsigned", "00000000000000000000000000000000"],
    "unknown_device": ["device999", ""],
    "caller_data_spoof": ["attacker-controlled", "999.9"],
}


def make_input(fdp, sandbox):
    devices = ["device001", "device002"]
    device = fdp.PickValueInList(devices)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(
            ["cross_device_signature", "altered_signature", "empty_or_garbage_signature"]
        )
        if technique == "cross_device_signature":
            signature = ATTACKS[technique][0 if device == "device001" else 1]
        elif technique == "altered_signature":
            signature = fdp.PickValueInList(ATTACKS[technique])
        else:
            signature = fdp.PickValueInList(ATTACKS[technique])

        if fdp.ConsumeBool():
            signature = (
                fdp.ConsumeUnicodeNoSurrogates(3)
                + signature
                + fdp.ConsumeUnicodeNoSurrogates(3)
            )
    else:
        signature = (
            "89ebf76ae45bfcf6dd7f2aa3de8b20b3"
            if device == "device001"
            else "1dcfa479db7aae3d40b3984cdf202de6"
        )

    if fdp.ConsumeBool():
        device = fdp.PickValueInList(ATTACKS["unknown_device"])

    packet_data = {}
    if fdp.ConsumeBool():
        packet_data = {
            "temperature": fdp.PickValueInList(ATTACKS["caller_data_spoof"]),
            "humidity": fdp.ConsumeIntInRange(-10, 110),
        }
    else:
        packet_data = {
            "temperature": fdp.ConsumeIntInRange(-10, 50),
            "humidity": fdp.ConsumeIntInRange(0, 100),
        }

    return {
        "id_device": device,
        "packet_signature": signature,
        "packet_data": packet_data,
    }
