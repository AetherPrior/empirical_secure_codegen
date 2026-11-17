ATTACKS = {
    "cross_user_signature": [
        "12e4b2f76650484030e4d447d0b5f723",
    ],
    "whitespace": [
        " 4e99a098d57cbf9c6f67f176106769fb",
        "4e99a098d57cbf9c6f67f176106769fb ",
        "\t4e99a098d57cbf9c6f67f176106769fb\n",
    ],
    "case_change": [
        "4E99A098D57CBF9C6F67F176106769FB",
    ],
    "truncation": [
        "4e99a098d57cbf9c6f67f176106769f",
        "4e99a098d57cbf9c6f67f176106769fb0",
    ],
    "wrapping": [
        "x4e99a098d57cbf9c6f67f176106769fb",
        "4e99a098d57cbf9c6f67f176106769fbx",
    ],
    "empty_or_null": [
        "",
        "\x004e99a098d57cbf9c6f67f176106769fb",
    ],
}


def make_input(fdp, sandbox):
    benign = [
        ("user_abc", "4e99a098d57cbf9c6f67f176106769fb"),
        ("user_xyz", "12e4b2f76650484030e4d447d0b5f723"),
    ]

    if not fdp.ConsumeBool():
        uid, sig = fdp.PickValueInList(benign)
        return {"uid": uid, "sig": sig}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    sig = fdp.PickValueInList(ATTACKS[technique])
    uid = "user_abc"

    if fdp.ConsumeBool():
        prefix = fdp.ConsumeUnicodeNoSurrogates(3)
        suffix = fdp.ConsumeUnicodeNoSurrogates(3)
        sig = prefix + sig + suffix

    return {"uid": uid, "sig": sig}
