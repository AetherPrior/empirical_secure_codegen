ATTACKS = {
    "cross_device_signature": [
        "1dcfa479db7aae3d40b3984cdf202de6",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
    ],
    "unknown_device": ["device003", "attacker"],
    "device_id_alias": ["Device001", "device001 ", "device001x"],
    "signature_mutation": [
        "",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b",
        "x89ebf76ae45bfcf6dd7f2aa3de8b20b3",
    ],
    "signature_whitespace": [
        " 89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "89ebf76ae45bfcf6dd7f2aa3de8b20b3 ",
    ],
}


def make_input(fdp, sandbox):
    trusted = {
        "device001": "89ebf76ae45bfcf6dd7f2aa3de8b20b3",
        "device002": "1dcfa479db7aae3d40b3984cdf202de6",
    }

    if not fdp.ConsumeBool():
        iot_id = fdp.PickValueInList(["device001", "device002"])
        return {
            "iot_id": iot_id,
            "crypto_signature": trusted[iot_id],
            "packet_info": {},
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "cross_device_signature":
        iot_id = "device001" if payload == trusted["device002"] else "device002"
        crypto_signature = payload
    elif technique in ("unknown_device", "device_id_alias"):
        iot_id = payload
        crypto_signature = trusted["device001"]
    else:
        iot_id = "device001"
        crypto_signature = payload

    if fdp.ConsumeBool() and technique in (
        "signature_mutation",
        "signature_whitespace",
    ):
        fuzz_text = fdp.ConsumeUnicodeNoSurrogates(3)
        if fdp.ConsumeBool():
            crypto_signature = fuzz_text + crypto_signature
        else:
            crypto_signature += fuzz_text

    return {
        "iot_id": iot_id,
        "crypto_signature": crypto_signature,
        "packet_info": {},
    }
