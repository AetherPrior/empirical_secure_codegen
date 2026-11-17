ATTACKS = {
    "privilege_escalation": ["admin", "moderator"],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        actor_id = fdp.PickValueInList([2, 3, 4])
        recipient_id = fdp.ConsumeIntInRange(1, 4)
        updated_privilege = fdp.PickValueInList(
            ATTACKS[fdp.PickValueInList(sorted(ATTACKS))]
        )
    else:
        actor_id = 1
        recipient_id = fdp.ConsumeIntInRange(2, 4)
        updated_privilege = "normal"

    return {
        "actor_id": actor_id,
        "recipient_id": recipient_id,
        "updated_privilege": updated_privilege,
    }
