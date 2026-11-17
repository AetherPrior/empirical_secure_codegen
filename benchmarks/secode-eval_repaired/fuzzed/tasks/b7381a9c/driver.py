ATTACKS = {
    "role_case": ["EDITOR", "Editor"],
    "role_whitespace": [" editor", "editor ", "editor\t", "editor\n"],
    "role_near_miss": ["editorial", "not-editor", "viewer;editor"],
    "role_null": ["editor\x00", "viewer\x00editor"],
    "owner_identity_mismatch": ["user444", "user111 ", " user111", "USER111"],
    "owner_identity_null": ["user111\x00", "\x00user111"],
}

def make_input(fdp, sandbox):
    document_id = fdp.PickValueInList(["doc123", "doc456"])
    actual_owner = "user111" if document_id == "doc123" else "user222"

    mode = fdp.ConsumeIntInRange(0, 5)
    if mode == 0:
        user_id, owner_id, user_role = actual_owner, actual_owner, "viewer"
    elif mode == 1:
        user_id, owner_id, user_role = "user444", actual_owner, "viewer"
    elif mode == 2:
        user_id, owner_id, user_role = "user444", actual_owner, "editor"
    elif mode == 3:
        family = fdp.PickValueInList(
            ["role_case", "role_whitespace", "role_near_miss", "role_null"]
        )
        user_id, owner_id = "user444", actual_owner
        user_role = fdp.PickValueInList(ATTACKS[family])
    elif mode == 4:
        family = fdp.PickValueInList(
            ["owner_identity_mismatch", "owner_identity_null"]
        )
        user_id, user_role = actual_owner, "viewer"
        owner_id = fdp.PickValueInList(ATTACKS[family])
    else:
        user_id = fdp.ConsumeUnicodeNoSurrogates(8)
        owner_id = fdp.ConsumeUnicodeNoSurrogates(8)
        user_role = fdp.PickValueInList(["viewer", "editor"])

    if fdp.ConsumeBool():
        new_content = "Updated content"
    else:
        new_content = fdp.ConsumeUnicodeNoSurrogates(24)

    return {
        "user_id": user_id,
        "user_role": user_role,
        "document_id": document_id,
        "owner_id": owner_id,
        "new_content": new_content,
    }
