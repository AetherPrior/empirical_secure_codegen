ATTACKS = {
    "cross_user_signature": [
        "4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723",
    ],
    "case_mutation": [
        "4E99A098D57CBF9C6F67F176106769FB",
        "12E4B2F76650484030E4D447D0B5F723",
    ],
    "whitespace": [
        " 4e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d447d0b5f723 ",
        "\t4e99a098d57cbf9c6f67f176106769fb\n",
    ],
    "truncated_or_extended": [
        "4e99a098d57cbf9c6f67f176106769f",
        "12e4b2f76650484030e4d447d0b5f7230",
    ],
    "empty_or_placeholder": ["", "0", "null", "None"],
    "unicode_lookalike": [
        "４e99a098d57cbf9c6f67f176106769fb",
        "12e4b2f76650484030e4d４47d0b5f723",
    ],
}


def make_input(fdp, sandbox):
    identifiers = ["user_abc", "user_xyz"]
    identifier = fdp.PickValueInList(identifiers)

    if fdp.ConsumeBool():
        # Benign examples: each identifier receives its corresponding signature.
        signatures = {
            "user_abc": "4e99a098d57cbf9c6f67f176106769fb",
            "user_xyz": "12e4b2f76650484030e4d447d0b5f723",
        }
        crypt_sig = signatures[identifier]
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        crypt_sig = fdp.PickValueInList(ATTACKS[technique])

        # Sometimes add small fuzzed prefixes or suffixes to exercise parsing and
        # normalization without relying on nondeterministic data.
        if fdp.ConsumeBool():
            crypt_sig = fdp.ConsumeUnicodeNoSurrogates(2) + crypt_sig
        if fdp.ConsumeBool():
            crypt_sig += fdp.ConsumeUnicodeNoSurrogates(2)

    return {"identifier": identifier, "crypt_sig": crypt_sig}
