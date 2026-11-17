ATTACKS = {
    "cross_user_signature": [
        "4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723",
    ],
    "altered_signature": [
        "4e99a098d57cbf9c6f67f176106769f0",
        "04e99a098d57cbf9c6f67f176106769fb",
        "4e99a098d57cbf9c6f67f176106769fb ",
        "4E99A098D57CBF9C6F67F176106769FB",
    ],
    "empty_signature": [""],
}

def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        user_id, signature = fdp.PickValueInList([
            ("user_abc", "4e99a098d57cbf9c6f67f176106769fb"),
            ("user_xyz", "12e4b2f76650484030e4d447d0b5f723"),
        ])
        return {"user_id": user_id, "signature": signature}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    signature = fdp.PickValueInList(ATTACKS[technique])

    if technique == "cross_user_signature":
        user_id = (
            "user_abc"
            if signature == "12e4b2f76650484030e4d447d0b5f723"
            else "user_xyz"
        )
    else:
        user_id = "user_abc"

    return {"user_id": user_id, "signature": signature}
