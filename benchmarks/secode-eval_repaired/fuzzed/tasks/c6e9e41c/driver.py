ATTACKS = {
    "cross_device_signature": [
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "1dcfa479db7aae3d40b3984cdf202de6",
    ],
    "signature_tampering": [
        "89ebf76ae45bfcf6dd7f2aa3de8b20b",
        "x89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "89EBF76AE45BFCF6DD7F2AA3DE8B20B3",
        "",
        " ",
    ],
    "unknown_device": [
        "device999",
        "device001x",
        "DEVICE001",
        "",
    ],
}


def make_input(fdp, sandbox):
    benign = {
        "device001": "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "device002": "1dcfa479db7aae3d40b3984cdf202de6",
    }

    payload = {"temperature": 22.5, "humidity": 60}

    if not fdp.ConsumeBool():
        device = fdp.PickValueInList(sorted(benign))
        sig = benign[device]
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        if technique == "cross_device_signature":
            sig = fdp.PickValueInList(ATTACKS[technique])
            device = (
                "device001"
                if sig == benign["device002"]
                else "device002"
            )
        elif technique == "signature_tampering":
            device = fdp.PickValueInList(sorted(benign))
            sig = fdp.PickValueInList(ATTACKS[technique])
        else:
            device = fdp.PickValueInList(ATTACKS[technique])
            sig = fdp.PickValueInList(ATTACKS["cross_device_signature"])

    return {"device": device, "sig": sig, "payload": payload}
