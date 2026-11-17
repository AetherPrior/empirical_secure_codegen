ATTACKS = {
    "non_creator_member": ["USER2", "USER3", "USER5"],
    "non_privileged_role": ["team_member", "viewer"],
    "role_spelling_confusion": ["PROJECT_MANAGER", "project_manager ", "project-manager"],
    "project_id": ["PROJ001", "PROJ002"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        member_id = fdp.PickValueInList(ATTACKS["non_creator_member"])
        project_key = "PROJ002" if member_id == "USER5" else "PROJ001"
        role_family = (
            "role_spelling_confusion"
            if fdp.ConsumeBool()
            else "non_privileged_role"
        )
        role = fdp.PickValueInList(ATTACKS[role_family])
    else:
        project_key = fdp.PickValueInList(["PROJ001", "PROJ002"])
        member_id = "USER1" if project_key == "PROJ001" else "USER4"
        role = fdp.PickValueInList(["team_member", "viewer", "project_manager"])

    settings = fdp.PickValueInList([
        {"visibility": "public"},
        {"deadline": "2024-01-01"},
        {"visibility": "private", "deadline": "2024-06-30"},
    ])
    return {
        "member_id": member_id,
        "role": role,
        "project_key": project_key,
        "updated_configuration": settings,
    }
