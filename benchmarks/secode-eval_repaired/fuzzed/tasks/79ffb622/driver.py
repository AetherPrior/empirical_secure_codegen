ATTACKS = {
    "self_escalation": [
        "2,2,admin",
        "3,3,admin",
    ],
    "peer_escalation": [
        "2,3,admin",
        "3,2,admin",
    ],
    "moderator_escalation": [
        "4,2,admin",
        "4,3,admin",
    ],
    "moderator_self_escalation": [
        "4,4,admin",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        requester, target, privilege = payload.split(",")
        return {
            "requesting_user_id": int(requester),
            "user_to_change_id": int(target),
            "desired_privilege": privilege,
        }

    return {
        "requesting_user_id": 1,
        "user_to_change_id": fdp.PickValueInList([2, 3, 4]),
        "desired_privilege": fdp.PickValueInList(["normal", "moderator"]),
    }
