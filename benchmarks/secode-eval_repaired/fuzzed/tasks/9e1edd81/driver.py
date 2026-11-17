ATTACKS = {
    "unauthorized_add": [
        "2,102,add,2",
        "3,103,add,3",
        "4,101,add,4",
    ],
    "unauthorized_remove": [
        "2,102,remove,3",
        "4,101,remove,2",
        "3,101,remove,3",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        active_user_id, proj_id, operation, target_member_id = payload.split(",")
        return {
            "active_user_id": int(active_user_id),
            "proj_id": int(proj_id),
            "operation": operation,
            "target_member_id": int(target_member_id),
        }

    benign_cases = [
        (1, 101, "add", 4),
        (1, 101, "remove", 2),
        (2, 101, "remove", 3),
        (3, 102, "add", 2),
        (4, 103, "add", 2),
    ]
    active_user_id, proj_id, operation, target_member_id = fdp.PickValueInList(
        benign_cases
    )
    return {
        "active_user_id": active_user_id,
        "proj_id": proj_id,
        "operation": operation,
        "target_member_id": target_member_id,
    }
