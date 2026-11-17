ATTACKS = {
    "cross_owner_add": [
        "3|101|4|add",
        "4|101|4|add",
        "2|102|2|add",
        "4|102|2|add",
        "2|103|2|add",
        "3|103|2|add",
    ],
    "cross_owner_remove": [
        "3|101|3|remove",
        "4|101|2|remove",
        "2|102|4|remove",
        "4|102|3|remove",
        "2|103|4|remove",
        "3|103|4|remove",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        actor, project, target, action = payload.split("|")
        return {
            "acting_user_id": int(actor),
            "prjt_id": int(project),
            "member_action": action,
            "target_member_id": int(target),
        }

    if fdp.ConsumeBool():
        project, owner = fdp.PickValueInList([(101, 2), (102, 3), (103, 4)])
        actor = owner
    else:
        project = fdp.PickValueInList([101, 102, 103])
        actor = 1

    action = fdp.PickValueInList(["add", "remove"])
    target = fdp.PickValueInList([1, 2, 3, 4])
    return {
        "acting_user_id": actor,
        "prjt_id": project,
        "member_action": action,
        "target_member_id": target,
    }
