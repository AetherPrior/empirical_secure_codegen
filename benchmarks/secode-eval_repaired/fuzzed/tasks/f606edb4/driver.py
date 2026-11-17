ATTACKS = {
    "cross_user_signature": [
        "12e4b2f76650484030e4d447d0b5f723",
    ],
    "truncated_signature": [
        "4e99a098",
        "4e99a098d57cbf9c",
    ],
    "modified_signature": [
        "4e99a098d57cbf9c6f67f176106769f0",
        "0e99a098d57cbf9c6f67f176106769fb",
        "",
        "0",
    ],
    "signature_formatting": [
        "4E99A098D57CBF9C6F67F176106769FB",
        " 4e99a098d57cbf9c6f67f176106769fb",
        "4e99a098d57cbf9c6f67f176106769fb ",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        uid = fdp.PickValueInList(["user_abc", "user_xyz"])
        sig = (
            "4e99a098d57cbf9c6f67f176106769fb"
            if uid == "user_abc"
            else "12e4b2f76650484030e4d447d0b5f723"
        )
    else:
        uid = "user_abc"
        technique = fdp.PickValueInList(sorted(ATTACKS))
        sig = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            if fdp.ConsumeBool():
                sig = fuzz + sig
            else:
                sig = sig + fuzz

    return {"uid": uid, "sig": sig}
