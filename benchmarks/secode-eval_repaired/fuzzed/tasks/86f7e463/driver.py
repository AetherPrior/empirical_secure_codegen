ATTACKS = {
    "non_owner_add": [
        "2:102:add:2",
        "3:101:add:3",
        "4:101:add:4",
    ],
    "non_owner_remove": [
        "2:102:remove:4",
        "3:101:remove:2",
        "4:102:remove:3",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        acting_user_id, project_identifier, modification, user_to_update_id = (
            fdp.PickValueInList(ATTACKS[technique]).split(":")
        )
        return {
            "acting_user_id": int(acting_user_id),
            "project_identifier": int(project_identifier),
            "modification": modification,
            "user_to_update_id": int(user_to_update_id),
        }

    benign_inputs = [
        (1, 101, "add", 4),
        (1, 102, "remove", 4),
        (2, 101, "add", 4),
        (3, 102, "remove", 4),
        (4, 103, "add", 3),
    ]
    acting_user_id, project_identifier, modification, user_to_update_id = (
        fdp.PickValueInList(benign_inputs)
    )
    return {
        "acting_user_id": acting_user_id,
        "project_identifier": project_identifier,
        "modification": modification,
        "user_to_update_id": user_to_update_id,
    }
