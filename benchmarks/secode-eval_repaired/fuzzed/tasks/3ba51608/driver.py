ATTACKS = {
    "non_admin_actor": ["2", "3", "4"],
    "target_user": ["1", "2", "3", "4"],
    "privilege_escalation": ["admin", "moderator"],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        acting_id_text = fdp.PickValueInList(ATTACKS["non_admin_actor"])
        acting_user_id = int(acting_id_text)

        if fdp.ConsumeBool():
            targeted_user_id = acting_user_id
        else:
            targeted_user_id = int(
                fdp.PickValueInList(ATTACKS["target_user"])
            )

        privilege = fdp.PickValueInList(ATTACKS["privilege_escalation"])
        if fdp.ConsumeBool():
            fuzz_text = fdp.ConsumeUnicodeNoSurrogates(2)
            privilege = fuzz_text + privilege + fuzz_text
        new_privilege_level = privilege
    else:
        acting_user_id = 1
        targeted_user_id = fdp.PickValueInList([1, 2, 3, 4])
        new_privilege_level = fdp.PickValueInList(
            ["normal", "moderator", "admin"]
        )

    return {
        "acting_user_id": acting_user_id,
        "targeted_user_id": targeted_user_id,
        "new_privilege_level": new_privilege_level,
    }
