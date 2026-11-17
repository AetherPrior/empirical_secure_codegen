ATTACKS = {
    "privilege_escalation": ["admin", "moderator"],
    "privilege_downgrade": ["normal"],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        # An unauthorized user attempts to change their own or another user's privileges.
        curr_user_id = fdp.PickValueInList([2, 3, 4])
        targ_user_id = fdp.PickValueInList([1, 2, 3, 4])
        technique = fdp.PickValueInList(sorted(ATTACKS))
        privilege_change = fdp.PickValueInList(ATTACKS[technique])
    else:
        # Benign administrator change.
        curr_user_id = 1
        targ_user_id = fdp.PickValueInList([2, 3, 4])
        privilege_change = "normal"

    return {
        "curr_user_id": curr_user_id,
        "targ_user_id": targ_user_id,
        "privilege_change": privilege_change,
    }
