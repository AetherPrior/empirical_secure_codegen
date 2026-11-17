ATTACKS = {
    "cross_device_replay": [
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "1dcfa479db7aae3d40b3984cdf202de6",
    ],
    "malformed_signature": [
        "",
        "00000000000000000000000000000000",
        "not-a-signature",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3x",
        "1dcfa479db7aae3d40b3984cdf202de",
    ],
    "decorated_signature": [
        " 89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "1dcfa479db7aae3d40b3984cdf202de6 ",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3\n",
        "1dcfa479db7aae3d40b3984cdf202de6\n",
    ],
}


def make_input(fdp, sandbox):
    devices = ["device001", "device002"]
    trusted = {
        "device001": "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "device002": "1dcfa479db7aae3d40b3984cdf202de6",
    }
    device_id = fdp.PickValueInList(devices)

    if fdp.ConsumeBool():
        signature = trusted[device_id]
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        if technique == "cross_device_replay":
            other_device = "device002" if device_id == "device001" else "device001"
            signature = trusted[other_device]
        else:
            signature = fdp.PickValueInList(ATTACKS[technique])

        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(2)
            suffix = fdp.ConsumeUnicodeNoSurrogates(2)
            signature = prefix + signature + suffix

    return {"device_id": device_id, "signature": signature, "data": {}}
