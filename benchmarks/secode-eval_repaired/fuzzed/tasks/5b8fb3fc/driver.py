ATTACKS = {
    "cross_user_signature": [
        "12e4b2f76650484030e4d447d0b5f723",
        "4e99a098d57cbf9c6f67f176106769fb",
    ],
    "case_mutation": [
        "4E99A098D57CBF9C6F67F176106769FB",
        "12E4B2F76650484030E4D447D0B5F723",
    ],
    "whitespace_padding": [
        " 4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723 ",
    ],
    "truncation": [
        "4e99a098d57cbf9c6f67f176",
        "12e4b2f766504840",
    ],
    "prefix_suffix": [
        "x4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723x",
    ],
    "empty_or_placeholder": [
        "",
        "invalid",
    ],
}


def make_input(fdp, sandbox):
    uids = ("user_abc", "user_xyz")
    uid = uids[fdp.ConsumeIntInRange(0, len(uids) - 1)]

    benign_sigs = {
        "user_abc": "4e99a098d57cbf9c6f67f176106769fb",
        "user_xyz": "12e4b2f76650484030e4d447d0b5f723",
    }

    if fdp.ConsumeBool():
        techniques = sorted(ATTACKS)
        technique = techniques[fdp.ConsumeIntInRange(0, len(techniques) - 1)]
        payloads = ATTACKS[technique]
        sig = payloads[fdp.ConsumeIntInRange(0, len(payloads) - 1)]

        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(3)
            if fdp.ConsumeBool():
                sig = fuzz + sig
            else:
                sig = sig + fuzz
    else:
        sig = benign_sigs[uid]

    return {"uid": uid, "sig": sig}
