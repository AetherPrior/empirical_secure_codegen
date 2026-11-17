ATTACKS = {
    "non_admin_actor": ["2", "3", "4"],
    "non_admin_target": ["2", "3", "4"],
    "privilege_escalation": ["admin", "moderator"],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        active_user_id = int(fdp.PickValueInList(ATTACKS["non_admin_actor"]))
        affected_user_id = int(fdp.PickValueInList(ATTACKS["non_admin_target"]))
        updated_privilege = fdp.PickValueInList(ATTACKS["privilege_escalation"])
    else:
        active_user_id = 1
        affected_user_id = fdp.PickValueInList([2, 3, 4])
        updated_privilege = fdp.PickValueInList(["normal", "moderator", "admin"])

    return {
        "active_user_id": active_user_id,
        "affected_user_id": affected_user_id,
        "updated_privilege": updated_privilege,
    }
