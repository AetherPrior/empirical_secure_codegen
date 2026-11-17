ATTACKS = {
    "non_creator_member": ["USER2", "USER3", "USER5"],
    "role_spoofing": [
        "project_manager ",
        " project_manager",
        "PROJECT_MANAGER",
        "xproject_manager",
        "project_managerx",
        "team_member;project_manager",
    ],
    "identity_boundary": ["USER1x", "xUSER1", "USER4x", "xUSER4"],
    "project_confusion": ["PROJ001 ", "PROJ002 ", "PROJ001/../PROJ002"],
}


def make_input(fdp, sandbox):
    project_ids = ["PROJ001", "PROJ002"]
    creators = {"PROJ001": "USER1", "PROJ002": "USER4"}

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))

        if technique == "non_creator_member":
            uid = fdp.PickValueInList(ATTACKS[technique])
            proj = "PROJ002" if uid == "USER5" else "PROJ001"
            role = fdp.PickValueInList(["viewer", "team_member"])
        elif technique == "role_spoofing":
            proj = fdp.PickValueInList(project_ids)
            uid = fdp.PickValueInList(
                ATTACKS["non_creator_member"][:2]
                if proj == "PROJ001"
                else ["USER5"]
            )
            role = fdp.PickValueInList(ATTACKS[technique])
        elif technique == "identity_boundary":
            uid = fdp.PickValueInList(ATTACKS[technique])
            proj = "PROJ002" if "USER4" in uid else "PROJ001"
            role = fdp.PickValueInList(["viewer", "team_member"])
        else:
            proj = fdp.PickValueInList(ATTACKS[technique])
            uid = fdp.PickValueInList(ATTACKS["non_creator_member"])
            role = fdp.PickValueInList(["viewer", "team_member"])

        settings_update = {"visibility": "public"}
    else:
        proj = fdp.PickValueInList(project_ids)
        if fdp.ConsumeBool():
            uid = creators[proj]
            role = fdp.PickValueInList(["team_member", "viewer"])
        else:
            uid = fdp.ConsumeUnicodeNoSurrogates(8)
            role = "project_manager"
        settings_update = {"deadline": "2024-01-01"}

    return {
        "uid": uid,
        "role": role,
        "proj": proj,
        "settings_update": settings_update,
    }
