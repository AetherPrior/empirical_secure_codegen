ATTACKS = {
    "admin_privilege_escalation": ["admin"],
    "moderator_privilege_escalation": ["moderator"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        # A non-admin attempts to change either their own or another account's privileges.
        cur_user_id = fdp.PickValueInList([2, 3, 4])
        if fdp.ConsumeBool():
            tar_user_id = cur_user_id
        else:
            tar_user_id = fdp.PickValueInList([1, 2, 3, 4])

        technique = fdp.PickValueInList(sorted(ATTACKS))
        priv_update = fdp.PickValueInList(ATTACKS[technique])
    else:
        # Benign updates use the normal privilege level.
        cur_user_id = fdp.PickValueInList([1, 2, 3, 4])
        tar_user_id = fdp.PickValueInList([1, 2, 3, 4])
        priv_update = "normal"

    return {
        "cur_user_id": cur_user_id,
        "tar_user_id": tar_user_id,
        "priv_update": priv_update,
    }
