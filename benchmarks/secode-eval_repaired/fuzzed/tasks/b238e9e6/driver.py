ATTACKS = {
    "self_escalation": ["admin"],
    "other_user_escalation": ["admin"],
    "moderator_escalation": ["admin"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        new_role = fdp.PickValueInList(ATTACKS[technique])

        if technique == "moderator_escalation":
            acting_user_id = 4
        else:
            acting_user_id = fdp.PickValueInList([2, 3])

        if technique == "self_escalation":
            affected_user_id = acting_user_id
        else:
            targets = [uid for uid in (2, 3, 4) if uid != acting_user_id]
            affected_user_id = fdp.PickValueInList(targets)

        return {
            "acting_user_id": acting_user_id,
            "affected_user_id": affected_user_id,
            "new_role": new_role,
        }

    return {
        "acting_user_id": 1,
        "affected_user_id": fdp.PickValueInList([2, 3, 4]),
        "new_role": fdp.PickValueInList(["normal", "moderator"]),
    }
