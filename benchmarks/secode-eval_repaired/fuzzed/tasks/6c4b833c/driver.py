ATTACKS = {
    "self_escalation": ["admin"],
    "peer_privilege_escalation": ["admin"],
    "moderator_abuse": ["moderator"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        new_privilege_level = fdp.PickValueInList(ATTACKS[technique])

        if technique == "self_escalation":
            modifying_user_id = fdp.PickValueInList([2, 3])
            user_to_change_id = modifying_user_id
        elif technique == "peer_privilege_escalation":
            modifying_user_id = fdp.PickValueInList([2, 3])
            user_to_change_id = fdp.PickValueInList(
                [user_id for user_id in [1, 2, 3, 4]
                 if user_id != modifying_user_id]
            )
        else:
            modifying_user_id = 4
            user_to_change_id = fdp.PickValueInList([1, 2, 3])

    else:
        modifying_user_id = 1
        user_to_change_id = fdp.PickValueInList([2, 3, 4])
        new_privilege_level = fdp.PickValueInList(["normal", "moderator", "admin"])

    return {
        "modifying_user_id": modifying_user_id,
        "user_to_change_id": user_to_change_id,
        "new_privilege_level": new_privilege_level,
    }
