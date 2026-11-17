ATTACKS = {
    "unauthorized_member_role": ["team_member", "viewer"],
    "role_confusion": [
        "PROJECT_MANAGER",
        "Project_Manager",
        "project_manager ",
        " project_manager",
        "project_manager\x00",
        "viewer,project_manager",
        "not_project_manager",
        "project_managerx",
    ],
    "creator_identity_near_miss": [
        "USER1 ",
        " USER1",
        "user1",
        "USER4 ",
        " USER4",
        "user4",
    ],
    "project_id_alias": [
        "proj001",
        " PROJ001",
        "PROJ001 ",
        "proj002",
        " PROJ002",
        "PROJ002 ",
    ],
}

def make_input(fdp, sandbox):
    projects = [
        ("USER1", "USER2", "PROJ001"),
        ("USER4", "USER5", "PROJ002"),
    ]
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        creator, member, proj_id = fdp.PickValueInList(projects)

        if technique == "unauthorized_member_role":
            owner_id = member
            access_level = payload
        elif technique == "role_confusion":
            owner_id = member
            access_level = payload
        elif technique == "creator_identity_near_miss":
            owner_id = payload
            access_level = "viewer"
        else:
            owner_id = member
            access_level = "viewer"
            proj_id = payload

        if fdp.ConsumeBool():
            fuzz = fdp.ConsumeUnicodeNoSurrogates(2)
            if fdp.ConsumeBool():
                payload = fuzz + payload
            else:
                payload = payload + fuzz
            if technique in ("unauthorized_member_role", "role_confusion"):
                access_level = payload
            elif technique == "creator_identity_near_miss":
                owner_id = payload
            else:
                proj_id = payload
    else:
        creator, member, proj_id = fdp.PickValueInList(projects)
        owner_id = fdp.PickValueInList(
            [creator, member, "USER6", "USER7"]
        )
        access_level = fdp.PickValueInList(
            ["project_manager", "team_member", "viewer"]
        )

    modifications = fdp.PickValueInList([
        {"visibility": "public"},
        {"visibility": "private"},
        {"deadline": "2024-01-01"},
        {"visibility": "public", "deadline": "2024-06-30"},
    ])
    return {
        "owner_id": owner_id,
        "access_level": access_level,
        "proj_id": proj_id,
        "modifications": modifications,
    }
