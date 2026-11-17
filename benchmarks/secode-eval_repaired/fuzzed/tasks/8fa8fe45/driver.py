ATTACKS = {
    "unauthorized_member": ["USER2", "USER3", "USER5"],
    "unknown_user": ["GUEST", "USER999"],
    "non_privileged_role": ["viewer", "team_member"],
    "role_spoofing": [
        "Project_Manager",
        "PROJECT_MANAGER",
        "project_manager ",
        " project_manager",
        "project-manager",
        "project_manager\n",
    ],
}


def make_input(fdp, sandbox):
    projects = {
        "PROJ001": {"creator": "USER1", "members": ["USER2", "USER3"]},
        "PROJ002": {"creator": "USER4", "members": ["USER5"]},
    }
    proj_id = fdp.PickValueInList(["PROJ001", "PROJ002"])
    project = projects[proj_id]
    mode = fdp.ConsumeIntInRange(0, 5)

    if mode == 0:
        member_id = fdp.PickValueInList(
            [m for m in project["members"] if m in ATTACKS["unauthorized_member"]]
        )
        member_role = fdp.PickValueInList(ATTACKS["non_privileged_role"])
    elif mode == 1:
        member_id = project["creator"]
        member_role = fdp.PickValueInList(ATTACKS["non_privileged_role"])
    elif mode == 2:
        member_id = fdp.PickValueInList(ATTACKS["unknown_user"])
        member_role = "project_manager"
    elif mode == 3:
        member_id = fdp.PickValueInList(ATTACKS["unauthorized_member"])
        member_role = fdp.PickValueInList(ATTACKS["role_spoofing"])
    elif mode == 4:
        member_id = fdp.PickValueInList(ATTACKS["unknown_user"])
        member_role = fdp.PickValueInList(ATTACKS["non_privileged_role"])
    else:
        member_id = project["creator"]
        member_role = "project_manager"

    if fdp.ConsumeBool() and mode in (0, 3, 4):
        fuzz = fdp.ConsumeUnicodeNoSurrogates(3)
        if fdp.ConsumeBool():
            member_id = fuzz + member_id
        else:
            member_role = fuzz + member_role

    setting_key = fdp.PickValueInList(["visibility", "deadline"])
    setting_value = (
        fdp.PickValueInList(["private", "public"])
        if setting_key == "visibility"
        else fdp.PickValueInList(["2024-01-01", "2025-06-30"])
    )

    return {
        "member_id": member_id,
        "member_role": member_role,
        "proj_id": proj_id,
        "fresh_settings": {setting_key: setting_value},
    }
