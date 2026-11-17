ATTACKS = {
    "self_privilege_escalation": ["admin", "moderator"],
    "other_user_privilege_escalation": ["admin", "moderator"],
    "moderator_privilege_escalation": ["admin"],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        new_level = fdp.PickValueInList(ATTACKS[technique])

        if technique == "self_privilege_escalation":
            acting_user_id = fdp.PickValueInList([2, 3])
            user_id_to_change = acting_user_id
        elif technique == "moderator_privilege_escalation":
            acting_user_id = 4
            user_id_to_change = fdp.PickValueInList([2, 3])
        else:
            acting_user_id = fdp.PickValueInList([2, 3])
            user_id_to_change = fdp.PickValueInList([1, 4])

        return {
            "acting_user_id": acting_user_id,
            "user_id_to_change": user_id_to_change,
            "new_level": new_level,
        }

    return {
        "acting_user_id": 1,
        "user_id_to_change": fdp.PickValueInList([2, 3, 4]),
        "new_level": fdp.PickValueInList(["normal", "moderator", "admin"]),
    }
