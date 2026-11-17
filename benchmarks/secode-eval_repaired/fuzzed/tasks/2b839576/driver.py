ATTACKS = {
    "regular_user_ids": ["2", "3", "4"],
    "project_ids": ["101", "102", "103"],
    "member_user_ids": ["2", "3", "4"],
    "membership_actions": ["add", "remove"],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        if fdp.ConsumeBool():
            return {
                "active_user_id": 1,
                "prj_id": 101,
                "action_type": "add",
                "member_user_id": 4,
            }
        return {
            "active_user_id": 2,
            "prj_id": 101,
            "action_type": "remove",
            "member_user_id": 3,
        }

    owners = {101: 2, 102: 3, 103: 4}
    members = {101: [2, 3], 102: [3, 4], 103: [4]}

    active_user_id = int(fdp.PickValueInList(ATTACKS["regular_user_ids"]))
    project_choices = [
        project_id
        for project_id in ATTACKS["project_ids"]
        if owners[int(project_id)] != active_user_id
    ]
    prj_id = int(fdp.PickValueInList(project_choices))
    action_type = fdp.PickValueInList(ATTACKS["membership_actions"])

    if action_type == "add":
        candidates = [
            user_id
            for user_id in ATTACKS["member_user_ids"]
            if int(user_id) not in members[prj_id]
        ]
    else:
        candidates = [
            user_id
            for user_id in ATTACKS["member_user_ids"]
            if int(user_id) in members[prj_id]
        ]

    member_user_id = int(fdp.PickValueInList(candidates))
    return {
        "active_user_id": active_user_id,
        "prj_id": prj_id,
        "action_type": action_type,
        "member_user_id": member_user_id,
    }
