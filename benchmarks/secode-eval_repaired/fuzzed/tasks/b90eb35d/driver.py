ATTACKS = {
    "non_admin_actor": ["2", "3", "4"],
    "target_user": ["1", "2", "3", "4"],
    "privilege_escalation": ["admin", "moderator"],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        actor = int(fdp.PickValueInList(ATTACKS["non_admin_actor"]))
        if fdp.ConsumeBool():
            target = actor
        else:
            target = int(fdp.PickValueInList(ATTACKS["target_user"]))
        privilege = fdp.PickValueInList(ATTACKS["privilege_escalation"])
    else:
        actor = 1
        target = fdp.PickValueInList([2, 3, 4])
        privilege = fdp.PickValueInList(["normal", "moderator", "admin"])

    return {
        "current_user_id": actor,
        "target_user_id": target,
        "new_privilege": privilege,
    }
