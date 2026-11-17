ATTACKS = {
    "cross_user_signature": [
        "4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723",
    ],
    "truncated_signature": [
        "4e99a098d57cbf9c6f67f176106769f",
        "12e4b2f76650484030e4d447d0b5f72",
    ],
    "modified_signature": [
        "4e99a098d57cbf9c6f67f176106769f0",
        "02e4b2f76650484030e4d447d0b5f723",
    ],
    "case_variant": [
        "4E99A098D57CBF9C6F67F176106769FB",
        "12E4B2F76650484030E4D447D0B5F723",
    ],
    "whitespace_wrapped": [
        " 4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723 ",
    ],
    "empty_signature": [""],
}


def make_input(fdp, sandbox):
    identifiers = ["user_abc", "user_xyz"]
    expected = {
        "user_abc": "4e99a098d57cbf9c6f67f176106769fb",
        "user_xyz": "12e4b2f76650484030e4d447d0b5f723",
    }

    user_identifier = fdp.PickValueInList(identifiers)
    if not fdp.ConsumeBool():
        return {
            "user_identifier": user_identifier,
            "user_signature": expected[user_identifier],
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    if technique == "cross_user_signature":
        other_identifier = identifiers[1] if user_identifier == identifiers[0] else identifiers[0]
        user_signature = expected[other_identifier]
    else:
        user_signature = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
            if fdp.ConsumeBool():
                user_signature = fuzz + user_signature
            else:
                user_signature = user_signature + fuzz

    return {
        "user_identifier": user_identifier,
        "user_signature": user_signature,
    }
