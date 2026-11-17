ATTACKS = {
    "cross_user_replay": [
        "4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723",
    ],
    "trailing_data": [
        "4e99a098d57cbf9c6f67f176106769fb!",
        "12e4b2f76650484030e4d447d0b5f723!",
    ],
    "whitespace": [
        " 4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723 ",
    ],
    "case_malleability": [
        "4E99A098D57CBF9C6F67F176106769FB",
        "12E4B2F76650484030E4D447D0B5F723",
    ],
    "truncation": [
        "4e99a098d57cbf9c6f67f176",
        "12e4b2f76650484030e4d447",
    ],
    "null_byte_suffix": [
        "4e99a098d57cbf9c6f67f176106769fb\x00",
        "12e4b2f76650484030e4d447d0b5f723\x00",
    ],
    "empty_or_garbage": ["", "invalid-signature"],
}


def make_input(fdp, sandbox):
    trusted = {
        "user_abc": "4e99a098d57cbf9c6f67f176106769fb",
        "user_xyz": "12e4b2f76650484030e4d447d0b5f723",
    }
    u_id = fdp.PickValueInList(["user_abc", "user_xyz"])
    expected = trusted[u_id]

    if not fdp.ConsumeBool():
        sig_code = expected
    else:
        families = sorted(ATTACKS)
        family = fdp.PickValueInList(families)
        candidates = [value for value in ATTACKS[family] if value != expected]
        sig_code = fdp.PickValueInList(candidates)
        if fdp.ConsumeBool():
            sig_code += fdp.ConsumeUnicodeNoSurrogates(4)

    return {"u_id": u_id, "sig_code": sig_code}
