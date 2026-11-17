ATTACKS = {
    "member_without_manager_role": ["USER2", "USER3", "USER5"],
    "non_manager_role": ["viewer", "team_member"],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        project_id = fdp.PickValueInList(["PROJ001", "PROJ002"])
        user_id = fdp.PickValueInList(ATTACKS["member_without_manager_role"])
        user_role = fdp.PickValueInList(ATTACKS["non_manager_role"])
    else:
        project_id = fdp.PickValueInList(["PROJ001", "PROJ002"])
        if fdp.ConsumeBool():
            user_id = "USER1" if project_id == "PROJ001" else "USER4"
            user_role = "team_member"
        else:
            user_id = "UNLISTED_USER"
            user_role = "project_manager"

    setting_key = fdp.PickValueInList(["visibility", "deadline", "description"])
    setting_value = fdp.PickValueInList(["private", "public", "2024-01-01", "updated"])

    return {
        "user_id": user_id,
        "user_role": user_role,
        "project_id": project_id,
        "new_settings": {setting_key: setting_value},
    }
