ATTACKS = {
    "member_without_permission": ["USER2", "USER3", "USER5"],
    "untrusted_identity": ["ATTACKER", "", "USER4"],
    "role_lookalikes": [
        "viewer",
        "project_manager ",
        " project_manager",
        "PROJECT_MANAGER",
        "not_project_manager",
        "project_managerx",
    ],
}


def make_input(fdp, sandbox):
    settings_options = [
        {"visibility": "public"},
        {"visibility": "private"},
        {"deadline": "2024-01-01"},
    ]
    updated_values = fdp.PickValueInList(settings_options)

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        user_token = fdp.PickValueInList(ATTACKS[family])
        role = fdp.PickValueInList(ATTACKS["role_lookalikes"])

        if user_token == "USER5":
            project_ident = "PROJ002"
        elif user_token == "USER4":
            project_ident = "PROJ001"
        else:
            project_ident = fdp.PickValueInList(["PROJ001", "PROJ002"])
            if project_ident == "PROJ002" and user_token == "USER2":
                user_token = "USER5"
    else:
        user_token, role, project_ident = fdp.PickValueInList([
            ("USER1", "team_member", "PROJ001"),
            ("USER4", "auditor", "PROJ002"),
            ("GUEST", "project_manager", "PROJ001"),
            ("GUEST", "project_manager", "PROJ002"),
        ])

    return {
        "user_token": user_token,
        "role": role,
        "project_ident": project_ident,
        "updated_values": updated_values,
    }
