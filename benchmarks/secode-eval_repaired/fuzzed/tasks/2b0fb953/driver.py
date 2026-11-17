ATTACKS = {
    "owner_claim_spoofing": ["user333", "user444", "user999"],
    "role_confusion": ["admin", "EDITOR", "editor ", "viewer\u200b", "superuser"],
}

def make_input(fdp, sandbox):
    documents = {
        "doc123": "user111",
        "doc456": "user222",
    }
    file_id = fdp.PickValueInList(["doc123", "doc456"])
    actual_owner = documents[file_id]
    updated_content = fdp.ConsumeUnicodeNoSurrogates(24)

    if fdp.ConsumeBool():
        account_id = fdp.PickValueInList(ATTACKS["owner_claim_spoofing"])
        return {
            "account_id": account_id,
            "account_role": "viewer",
            "file_id": file_id,
            "owner_id": account_id,
            "updated_content": updated_content,
        }

    if fdp.ConsumeBool():
        return {
            "account_id": fdp.PickValueInList(ATTACKS["owner_claim_spoofing"]),
            "account_role": fdp.PickValueInList(ATTACKS["role_confusion"]),
            "file_id": file_id,
            "owner_id": actual_owner,
            "updated_content": updated_content,
        }

    if fdp.ConsumeBool():
        return {
            "account_id": actual_owner,
            "account_role": "viewer",
            "file_id": file_id,
            "owner_id": actual_owner,
            "updated_content": updated_content,
        }

    return {
        "account_id": "user-editor",
        "account_role": "editor",
        "file_id": file_id,
        "owner_id": actual_owner,
        "updated_content": updated_content,
    }
