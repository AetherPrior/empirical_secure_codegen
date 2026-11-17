ATTACKS = {
    "forged_owner": ["user444", "user999", "outsider"],
    "role_alias": ["EDITOR", "editor ", "administrator", "Editor"],
}

def make_input(fdp, sandbox):
    doc_id = fdp.PickValueInList(["doc123", "doc456"])
    actual_owner = {"doc123": "user111", "doc456": "user222"}[doc_id]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        if technique == "forged_owner":
            operator_id = fdp.PickValueInList(ATTACKS["forged_owner"])
            operator_role = "viewer"
            doc_owner_id = operator_id
        else:
            operator_id = fdp.PickValueInList(ATTACKS["forged_owner"])
            operator_role = fdp.PickValueInList(ATTACKS["role_alias"])
            doc_owner_id = actual_owner
        updated_content = fdp.ConsumeUnicodeNoSurrogates(32)
    else:
        operator_id = actual_owner if fdp.ConsumeBool() else "user333"
        operator_role = fdp.PickValueInList(["viewer", "editor"])
        doc_owner_id = actual_owner
        updated_content = fdp.PickValueInList(
            ["Updated document content", "A short benign revision"]
        )

    return {
        "operator_id": operator_id,
        "operator_role": operator_role,
        "doc_id": doc_id,
        "doc_owner_id": doc_owner_id,
        "updated_content": updated_content,
    }
