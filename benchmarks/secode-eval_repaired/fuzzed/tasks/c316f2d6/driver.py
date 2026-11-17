ATTACKS = {
    "cross_project_access": [
        "2:102", "2:103",
        "3:101", "3:103",
        "4:101", "4:102",
    ],
}


def make_input(fdp, sandbox):
    projects = {
        101: {"owner_id": 2, "members": [2, 3]},
        102: {"owner_id": 3, "members": [3, 4]},
        103: {"owner_id": 4, "members": [4]},
    }

    if fdp.ConsumeBool():
        pair = fdp.PickValueInList(ATTACKS["cross_project_access"])
        actor_text, project_text = pair.split(":")
        current_user_id = int(actor_text)
        project_id = int(project_text)
    else:
        # Benign cases: an owner modifying their project, or an admin
        # modifying any project.
        current_user_id, project_id = fdp.PickValueInList(
            [(1, 101), (1, 102), (1, 103), (2, 101), (3, 102), (4, 103)]
        )

    action = "add" if fdp.ConsumeBool() else "remove"
    target_user_id = (
        1 if action == "add" else fdp.PickValueInList(projects[project_id]["members"])
    )

    return {
        "current_user_id": current_user_id,
        "project_id": project_id,
        "action": action,
        "target_user_id": target_user_id,
    }
