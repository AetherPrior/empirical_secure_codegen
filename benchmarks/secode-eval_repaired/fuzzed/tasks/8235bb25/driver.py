ATTACKS = {
    "member_only": ["USER2", "USER3", "USER5"],
    "role_spoofing": ["Project_Manager", "PROJECT_MANAGER", "project_manager ", "admin", "owner"],
    "nonmember": ["USER9"],
}


def make_input(fdp, sandbox):
    projects = {
        "PROJ001": ("USER1", ["USER2", "USER3"]),
        "PROJ002": ("USER4", ["USER5"]),
    }
    proj_id = fdp.PickValueInList(["PROJ001", "PROJ002"])

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(["member_only", "role_spoofing"])
        if technique == "member_only":
            u_id = fdp.PickValueInList(ATTACKS["member_only"])
            if u_id == "USER5":
                proj_id = "PROJ002"
            else:
                proj_id = "PROJ001"
            u_role = fdp.PickValueInList(["team_member", "viewer"])
        else:
            u_id = fdp.PickValueInList(ATTACKS["nonmember"])
            u_role = fdp.PickValueInList(ATTACKS["role_spoofing"])
    else:
        creator, _ = projects[proj_id]
        if fdp.ConsumeBool():
            u_id, u_role = creator, fdp.PickValueInList(["team_member", "viewer"])
        else:
            u_id, u_role = fdp.PickValueInList(ATTACKS["nonmember"]), "project_manager"

    key = fdp.PickValueInList(["visibility", "deadline"])
    value = (
        fdp.PickValueInList(["public", "private", "2024-01-01"])
        if fdp.ConsumeBool()
        else fdp.ConsumeUnicodeNoSurrogates(8)
    )

    return {
        "u_id": u_id,
        "u_role": u_role,
        "proj_id": proj_id,
        "modified_settings": {key: value},
    }
