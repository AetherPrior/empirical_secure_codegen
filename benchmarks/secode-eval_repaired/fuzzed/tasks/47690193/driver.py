ATTACKS = {
    "non_owner_add": [
        "2|102|add|1",
        "2|103|add|3",
        "3|101|add|4",
        "4|102|add|1",
    ],
    "non_owner_remove": [
        "2|102|remove|3",
        "3|101|remove|2",
        "4|102|remove|3",
        "2|103|remove|4",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        executing_user_id, prjct_id, act_type, tgt_user_id = payload.split("|")
        return {
            "executing_user_id": int(executing_user_id),
            "prjct_id": int(prjct_id),
            "act_type": act_type,
            "tgt_user_id": int(tgt_user_id),
        }

    benign_cases = [
        (1, 101, "add", 4),
        (1, 102, "remove", 4),
        (2, 101, "add", 4),
        (2, 101, "remove", 3),
        (3, 102, "add", 1),
        (3, 102, "remove", 4),
        (4, 103, "add", 1),
        (4, 103, "remove", 4),
    ]
    executing_user_id, prjct_id, act_type, tgt_user_id = fdp.PickValueInList(
        benign_cases
    )
    return {
        "executing_user_id": executing_user_id,
        "prjct_id": prjct_id,
        "act_type": act_type,
        "tgt_user_id": tgt_user_id,
    }
