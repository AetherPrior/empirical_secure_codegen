ATTACKS = {
    "cross_user_replay": [
        "4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723",
    ],
    "uppercase": [
        "4E99A098D57CBF9C6F67F176106769FB",
        "12E4B2F76650484030E4D447D0B5F723",
    ],
    "whitespace": [
        " 4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723 ",
    ],
    "truncated": [
        "4e99a098d57cbf9c6f67f176106769",
        "12e4b2f76650484030e4d447d0b5",
    ],
    "extended": [
        "4e99a098d57cbf9c6f67f176106769fb0",
        "012e4b2f76650484030e4d447d0b5f723",
    ],
    "malformed": [
        "",
        "not-a-signature",
        "4e99a098d57cbf9c6f67f176106769fG",
    ],
}


def make_input(fdp, sandbox):
    users = {
        "user_abc": "4e99a098d57cbf9c6f67f176106769fb",
        "user_xyz": "12e4b2f76650484030e4d447d0b5f723",
    }

    if not fdp.ConsumeBool():
        profile_id = fdp.PickValueInList(list(users))
        return {
            "profile_id": profile_id,
            "profile_sig": users[profile_id],
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    profile_sig = fdp.PickValueInList(ATTACKS[technique])

    if technique == "cross_user_replay":
        profile_id = (
            "user_xyz"
            if profile_sig == users["user_abc"]
            else "user_abc"
        )
    else:
        profile_id = fdp.PickValueInList(list(users))

    if fdp.ConsumeBool():
        prefix = fdp.ConsumeUnicodeNoSurrogates(2)
        suffix = fdp.ConsumeUnicodeNoSurrogates(2)
        profile_sig = prefix + profile_sig + suffix

    return {"profile_id": profile_id, "profile_sig": profile_sig}
