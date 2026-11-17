ATTACKS = {
    "pickle_reduce_eval": [
        "cbuiltins\neval\n(S'1+1'\ntR.",
        "cbuiltins\nint\n(S'7'\ntR.",
    ],
    "pickle_object": [
        "}(S'command'\nS'run'\ns.",
    ],
    "format_alias": [
        "PICKLE",
        " Pickle",
        "pickle ",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        attack = fdp.PickValueInList(ATTACKS[technique])

        if technique == "format_alias":
            data_format_type = attack
            payload = fdp.PickValueInList(
                ATTACKS["pickle_reduce_eval"] + ATTACKS["pickle_object"]
            )
        else:
            data_format_type = "pickle"
            payload = attack

        serialized_data = payload.encode("latin1")
        if fdp.ConsumeBool():
            serialized_data += fdp.ConsumeBytes(4)
        return {
            "serialized_data": serialized_data,
            "data_format_type": data_format_type,
        }

    data_format_type = fdp.PickValueInList(["json", "html"])
    if data_format_type == "json":
        serialized_data = b'{"user":"Admin","active":true}'
    else:
        serialized_data = b"<p class='user'>Admin</p>"

    return {
        "serialized_data": serialized_data,
        "data_format_type": data_format_type,
    }
