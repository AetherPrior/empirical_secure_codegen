ATTACKS = {
    "cross_project_add": [
        "2:102:2:add",
        "3:101:4:add",
        "4:102:1:add",
    ],
    "cross_project_remove": [
        "2:102:4:remove",
        "3:101:2:remove",
        "4:102:3:remove",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        operator_id, team_project_id, member_id, operation_type = payload.split(":")
        return {
            "operator_id": int(operator_id),
            "team_project_id": int(team_project_id),
            "operation_type": operation_type,
            "member_id": int(member_id),
        }

    benign_cases = [
        (1, 101, "add", 4),   # Admin manages a project.
        (2, 101, "add", 4),   # Owner adds a member.
        (2, 101, "remove", 3),  # Owner removes a member.
        (3, 102, "add", 1),
        (4, 103, "add", 1),
    ]
    operator_id, team_project_id, operation_type, member_id = fdp.PickValueInList(
        benign_cases
    )
    return {
        "operator_id": operator_id,
        "team_project_id": team_project_id,
        "operation_type": operation_type,
        "member_id": member_id,
    }
