ATTACKS = {
    "wrong_user_signature": [
        "12e4b2f76650484030e4d447d0b5f723",
    ],
    "empty_or_truncated": [
        "",
        "4e99a098d57cbf9c6f67f176106769f",
        "4e99a098d57cbf9c6f67f176106769fb0",
    ],
    "format_variants": [
        "4E99A098D57CBF9C6F67F176106769FB",
        " 4e99a098d57cbf9c6f67f176106769fb",
        "4e99a098d57cbf9c6f67f176106769fb ",
        "0x4e99a098d57cbf9c6f67f176106769fb",
        "4e99a098d57cbf9c6f67f176106769fb\n",
    ],
    "malformed_signature": [
        "not-a-signature",
        "00000000000000000000000000000000",
        "4e99a098d57cbf9c6f67f176106769f\u0000",
        "４e99a098d57cbf9c6f67f176106769fb",
    ],
}


def make_input(fdp, sandbox):
    user_ident = fdp.PickValueInList(["user_abc", "user_xyz"])

    if fdp.ConsumeBool():
        user_ident = "user_abc"
        family = fdp.PickValueInList(sorted(ATTACKS))
        user_sig = fdp.PickValueInList(ATTACKS[family])

        if fdp.ConsumeBool():
            fuzz_text = fdp.ConsumeUnicodeNoSurrogates(4)
            if fuzz_text:
                if fdp.ConsumeBool():
                    user_sig = fuzz_text + user_sig
                else:
                    user_sig = user_sig + fuzz_text
    else:
        user_sig = {
            "user_abc": "4e99a098d57cbf9c6f67f176106769fb",
            "user_xyz": "12e4b2f76650484030e4d447d0b5f723",
        }[user_ident]

    return {"user_ident": user_ident, "user_sig": user_sig}
