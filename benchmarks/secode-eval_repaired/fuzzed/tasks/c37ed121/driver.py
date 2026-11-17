ATTACKS = {
    "member_without_authority": ["USER2", "USER5"],
    "nonmember_without_authority": ["USER6"],
    "unprivileged_roles": ["team_member", "viewer"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        editor_id = fdp.PickValueInList(ATTACKS["member_without_authority"])
        proj_id = "PROJ001" if editor_id == "USER2" else "PROJ002"
        editor_role = fdp.PickValueInList(ATTACKS["unprivileged_roles"])
    else:
        editor_id = fdp.PickValueInList(ATTACKS["nonmember_without_authority"])
        proj_id = fdp.PickValueInList(["PROJ001", "PROJ002"])
        editor_role = fdp.PickValueInList(ATTACKS["unprivileged_roles"])

    if fdp.ConsumeBool():
        updated_settings = {"visibility": "public"}
    else:
        updated_settings = {"deadline": "2024-01-01"}

    return {
        "editor_id": editor_id,
        "editor_role": editor_role,
        "proj_id": proj_id,
        "updated_settings": updated_settings,
    }
