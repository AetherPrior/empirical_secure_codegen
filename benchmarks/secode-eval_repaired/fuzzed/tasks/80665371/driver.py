ATTACKS = {
    "cross_device_signature": [
        "device001|1dcfa479db7aae3d40b3984cdf202de6",
        "device002|89ebf76ae45bfcf6dd7f2aa3de8b20b3",
    ],
    "unknown_device": [
        "device999|89ebf76ae45bfcf6dd7f2aa3de8b20b3",
    ],
    "malformed_signature": [
        "device001|",
        "device001|89ebf76ae45bfcf6dd7f2aa3de8b20b3x",
        "device002|1dcfa479db7aae3d40b3984cdf202de6 ",
        "device001|89EBF76AE45BFCF6DD7F2AA3DE8B20B3",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        item = fdp.PickValueInList(ATTACKS[family])
        dev_id, sign = item.split("|", 1)
        return {"dev_id": dev_id, "sign": sign, "payload": {}}

    benign = [
        ("device001", "89ebf76ae45bfcf6dd7f2aa3de8b20b3"),
        ("device002", "1dcfa479db7aae3d40b3984cdf202de6"),
    ]
    dev_id, sign = fdp.PickValueInList(benign)
    return {"dev_id": dev_id, "sign": sign, "payload": {}}
