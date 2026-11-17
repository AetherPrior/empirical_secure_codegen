ATTACKS = {
    "forged_creator_id": ["user444", "user999"],
    "non_editor_role": ["viewer", "VIEWER", "viewer ", "administrator", ""],
}


def make_input(fdp, sandbox):
    documents = [
        ("doc123", "user111"),
        ("doc456", "user222"),
    ]
    doc_identifier, actual_owner = fdp.PickValueInList(documents)
    updated_content = fdp.ConsumeUnicodeNoSurrogates(24)

    if fdp.ConsumeBool():
        # Claim an attacker is the creator, despite the document's actual owner.
        attacker = fdp.PickValueInList(ATTACKS["forged_creator_id"])
        suffix = fdp.ConsumeUnicodeNoSurrogates(4)
        claimed_creator = attacker + suffix
        return {
            "modifier_id": claimed_creator,
            "user_role": "viewer",
            "doc_identifier": doc_identifier,
            "creator_id": claimed_creator,
            "updated_content": updated_content,
        }

    if fdp.ConsumeBool():
        # Try non-editor role values while the caller is not the document owner.
        attacker = fdp.PickValueInList(ATTACKS["forged_creator_id"])
        suffix = fdp.ConsumeUnicodeNoSurrogates(4)
        return {
            "modifier_id": attacker + suffix,
            "user_role": fdp.PickValueInList(ATTACKS["non_editor_role"]),
            "doc_identifier": doc_identifier,
            "creator_id": actual_owner,
            "updated_content": updated_content,
        }

    # Benign owner or editor cases.
    if fdp.ConsumeBool():
        modifier_id = actual_owner
        user_role = "viewer"
    else:
        modifier_id = fdp.PickValueInList(["user333", "user555"])
        user_role = "editor"

    return {
        "modifier_id": modifier_id,
        "user_role": user_role,
        "doc_identifier": doc_identifier,
        "creator_id": actual_owner,
        "updated_content": updated_content,
    }
