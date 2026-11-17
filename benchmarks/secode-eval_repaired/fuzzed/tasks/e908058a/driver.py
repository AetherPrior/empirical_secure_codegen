ATTACKS = {
    "cross_user_signature": [
        "4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723",
    ],
    "tampered_signature": [
        "4e99a098d57cbf9c6f67f176106769f0",
        "12e4b2f76650484030e4d447d0b5f720",
        "not-a-signature",
        "",
    ],
    "signature_formatting": [
        " 4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723 ",
        "4E99A098D57CBF9C6F67F176106769FB",
        "0x12e4b2f76650484030e4d447d0b5f723",
    ],
}


def make_input(fdp, sandbox):
    users = [
        ("user_abc", "4e99a098d57cbf9c6f67f176106769fb"),
        ("user_xyz", "12e4b2f76650484030e4d447d0b5f723"),
    ]

    if not fdp.ConsumeBool():
        uuid, sig_hash = fdp.PickValueInList(users)
        return {"uuid": uuid, "sig_hash": sig_hash}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "cross_user_signature":
        uuid = (
            "user_abc"
            if payload == "12e4b2f76650484030e4d447d0b5f723"
            else "user_xyz"
        )
        sig_hash = payload
    else:
        uuid, _ = fdp.PickValueInList(users)
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        sig_hash = prefix + payload + suffix

    return {"uuid": uuid, "sig_hash": sig_hash}
