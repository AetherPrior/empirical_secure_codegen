ATTACKS = {
    "member_without_authority": [
        "USER2|team_member|PROJ001",
        "USER3|viewer|PROJ001",
        "USER5|viewer|PROJ002",
    ],
    "role_spoof": [
        "USER2|project_managerx|PROJ001",
        "USER2|Project_Manager|PROJ001",
        "USER5| project_manager|PROJ002",
        "USER5|project_manager |PROJ002",
    ],
    "nonmember_without_authority": [
        "USER999|team_member|PROJ001",
        "USER999|viewer|PROJ002",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        emp_id, role, proj_id = fdp.PickValueInList(ATTACKS[technique]).split("|")
    else:
        # Benign cases include project creators and a project manager.
        emp_id, role, proj_id = fdp.PickValueInList([
            ("USER1", "team_member", "PROJ001"),
            ("USER4", "viewer", "PROJ002"),
            ("USER999", "project_manager", "PROJ001"),
        ])

    key = fdp.PickValueInList(["visibility", "deadline"])
    value = fdp.PickValueInList(["public", "private", "2024-01-01"])
    return {
        "emp_id": emp_id,
        "role": role,
        "proj_id": proj_id,
        "updated_settings": {key: value},
    }
