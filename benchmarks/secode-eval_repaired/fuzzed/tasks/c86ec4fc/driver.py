ATTACKS = {
    "non_owner_add": ["2|102|add|4", "4|101|add|3"],
    "non_owner_remove": ["2|102|remove|4", "4|101|remove|3"],
    "unknown_actor": ["99|101|add|4", "0|102|remove|4"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        acting_user_id, prj_id, action_type, target_id = payload.split("|")
        return {
            "acting_user_id": int(acting_user_id),
            "prj_id": int(prj_id),
            "action_type": action_type,
            "target_id": int(target_id),
        }

    benign_samples = [
        (1, 101, "add", 4),
        (1, 102, "remove", 4),
        (2, 101, "add", 4),
        (3, 102, "remove", 4),
        (4, 103, "add", 2),
    ]
    acting_user_id, prj_id, action_type, target_id = fdp.PickValueInList(
        benign_samples
    )
    return {
        "acting_user_id": acting_user_id,
        "prj_id": prj_id,
        "action_type": action_type,
        "target_id": target_id,
    }
