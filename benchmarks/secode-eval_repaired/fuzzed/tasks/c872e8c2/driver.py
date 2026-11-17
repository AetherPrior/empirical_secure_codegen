ATTACKS = {
    "cross_device_signature_replay": [
        "1dcfa479db7aae3d40b3984cdf202de6",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
    ],
    "unknown_device": ["device999"],
    "signature_mutation": ["!", " "],
}


def make_input(fdp, sandbox):
    mode = fdp.ConsumeIntInRange(0, 4)

    if mode == 0:
        # Benign: exact signature for the identified device.
        io_device_id = fdp.PickValueInList(["device001", "device002"])
        crypto_signature = (
            "89ebf76ae45bfcf6dd7f2aa3de8b20b3"
            if io_device_id == "device001"
            else "1dcfa479db7aae3d40b3984cdf202de6"
        )
    elif mode in (1, 2):
        # Replay a trusted signature belonging to a different device.
        io_device_id = "device001" if mode == 1 else "device002"
        crypto_signature = fdp.PickValueInList(
            ATTACKS["cross_device_signature_replay"]
        )
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(2)
            crypto_signature = (
                fuzz + crypto_signature
                if fdp.ConsumeBool()
                else crypto_signature + fuzz
            )
    elif mode == 3:
        # Use a valid signature with an untrusted device identifier.
        io_device_id = fdp.PickValueInList(ATTACKS["unknown_device"])
        crypto_signature = "89ebf76ae45bfcf6dd7f2aa3de8b20b3"
        if fdp.ConsumeBool():
            io_device_id = (
                fdp.ConsumeUnicodeNoSurrogates(2)
                + io_device_id
            )
    else:
        # Mutate an otherwise correct signature.
        io_device_id = "device001"
        mutation = fdp.PickValueInList(ATTACKS["signature_mutation"])
        crypto_signature = (
            "89ebf76ae45bfcf6dd7f2aa3de8b20b3" + mutation
        )

    return {
        "io_device_id": io_device_id,
        "crypto_signature": crypto_signature,
        "packet_data": {},
    }
