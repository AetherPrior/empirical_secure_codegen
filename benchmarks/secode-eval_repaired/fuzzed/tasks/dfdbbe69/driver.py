ATTACKS = {
    "unauthorized_add": [
        "3,101,add,4",
        "4,101,add,4",
        "2,102,add,2",
        "4,102,add,2",
        "2,103,add,2",
        "3,103,add,2",
    ],
    "unauthorized_remove": [
        "4,101,remove,3",
        "2,102,remove,4",
        "2,103,remove,4",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        req_user_id, proj_id, mod, mod_user_id = payload.split(",")
        return {
            "req_user_id": int(req_user_id),
            "proj_id": int(proj_id),
            "mod": mod,
            "mod_user_id": int(mod_user_id),
        }

    # These actions are authorized and change project membership.
    benign = [
        (1, 101, "add", 4),
        (1, 101, "remove", 3),
        (2, 101, "add", 4),
        (2, 101, "remove", 3),
        (1, 102, "add", 2),
        (3, 102, "remove", 4),
        (1, 103, "add", 2),
        (4, 103, "remove", 4),
    ]
    req_user_id, proj_id, mod, mod_user_id = fdp.PickValueInList(benign)
    return {
        "req_user_id": req_user_id,
        "proj_id": proj_id,
        "mod": mod,
        "mod_user_id": mod_user_id,
    }
