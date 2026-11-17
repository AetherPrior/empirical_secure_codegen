ATTACKS = {
    "member_without_permission": ["USER2", "USER5"],
    "nonmember_identity": ["USER9"],
    "role_spoofing": [
        "viewer",
        "team_member",
        "project_manager ",
        " project_manager",
        "PROJECT_MANAGER",
        "not_project_manager",
        "project_manager_extra",
        "xproject_manager",
    ],
    "creator_identity_confusion": ["USER1 "],
}


def make_input(fdp, sandbox):
    scenario = fdp.ConsumeIntInRange(0, 5)

    if scenario == 0:
        pid = "PROJ002"
        uid = fdp.PickValueInList(ATTACKS["member_without_permission"])
        role = fdp.PickValueInList(["viewer", "team_member"])
    elif scenario == 1:
        pid = "PROJ001"
        uid = fdp.PickValueInList(ATTACKS["member_without_permission"])
        role = fdp.PickValueInList(["viewer", "team_member"])
    elif scenario == 2:
        pid = "PROJ002"
        uid = fdp.PickValueInList(ATTACKS["nonmember_identity"])
        role = fdp.PickValueInList(ATTACKS["role_spoofing"])
    elif scenario == 3:
        pid = "PROJ001"
        uid = "USER1"
        role = fdp.PickValueInList(["viewer", "team_member", "project_manager"])
    elif scenario == 4:
        pid = "PROJ002"
        uid = fdp.PickValueInList(ATTACKS["nonmember_identity"])
        role = "project_manager"
    else:
        pid = "PROJ001"
        uid = fdp.PickValueInList(ATTACKS["creator_identity_confusion"])
        role = "viewer"

    if fdp.ConsumeBool():
        noise = fdp.ConsumeUnicodeNoSurrogates(4)
        role = noise + role if fdp.ConsumeBool() else role + noise

    settings = (
        {"visibility": fdp.PickValueInList(["private", "public"])}
        if fdp.ConsumeBool()
        else {"deadline": fdp.PickValueInList(["2024-01-01", "2025-06-30"])}
    )
    return {"uid": uid, "role": role, "pid": pid, "settings": settings}
