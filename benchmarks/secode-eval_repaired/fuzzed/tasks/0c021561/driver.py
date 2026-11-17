ATTACKS = {
    "role_near_miss": [
        "Editor",
        "EDITOR",
        "editor ",
        " editor",
        "editorial",
        "viewer,editor",
    ],
    "identity_confusion": [
        "user444",
        "user111",
        "user222",
    ],
}


def make_input(fdp, sandbox):
    docu_id = fdp.PickValueInList(["doc123", "doc456"])
    owner_id = "user111" if docu_id == "doc123" else "user222"

    if fdp.ConsumeBool():
        usr_role = fdp.PickValueInList(ATTACKS["role_near_miss"])
    else:
        usr_role = fdp.PickValueInList(["editor", "viewer"])

    if fdp.ConsumeBool():
        usr_id = fdp.PickValueInList(ATTACKS["identity_confusion"])
    else:
        usr_id = fdp.PickValueInList(["user111", "user222", "user444"])

    if fdp.ConsumeBool():
        creator_id = fdp.PickValueInList(ATTACKS["identity_confusion"])
    else:
        creator_id = owner_id

    updated_definition = fdp.ConsumeUnicodeNoSurrogates(24)
    if not updated_definition:
        updated_definition = "Revised document content"

    return {
        "usr_id": usr_id,
        "usr_role": usr_role,
        "docu_id": docu_id,
        "creator_id": creator_id,
        "updated_definition": updated_definition,
    }
