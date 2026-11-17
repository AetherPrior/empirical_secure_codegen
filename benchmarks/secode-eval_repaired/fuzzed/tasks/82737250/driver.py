ATTACKS = {
    "unprivileged_requester": ["user444", "user000", "user999"],
    "forged_owner_claim": ["user444", "user000", "user999"],
    "role_confusion": ["viewer", "admin", "EDITOR", "editor "],
}


def make_input(fdp, sandbox):
    documents = [
        ("doc123", "user111"),
        ("doc456", "user222"),
    ]
    document_identifier, actual_owner = fdp.PickValueInList(documents)
    content = fdp.ConsumeUnicodeNoSurrogates(32)

    if fdp.ConsumeBool():
        attack_case = fdp.ConsumeIntInRange(0, 2)

        if attack_case == 0:
            # Ordinary unauthorized viewer request.
            requester_id = fdp.PickValueInList(
                ATTACKS["unprivileged_requester"]
            )
            requester_role = "viewer"
            document_owner_id = actual_owner
        elif attack_case == 1:
            # Claim ownership using an ID that differs from the stored owner.
            requester_id = fdp.PickValueInList(
                ATTACKS["forged_owner_claim"]
            )
            requester_role = "viewer"
            document_owner_id = requester_id
        else:
            # Test whether a non-editor role is treated as sufficient.
            requester_id = fdp.PickValueInList(
                ATTACKS["unprivileged_requester"]
            )
            requester_role = fdp.PickValueInList(ATTACKS["role_confusion"])
            document_owner_id = actual_owner
    else:
        if fdp.ConsumeBool():
            requester_id = actual_owner
            requester_role = "viewer"
        else:
            requester_id = "user333"
            requester_role = "editor"
        document_owner_id = actual_owner

    return {
        "requester_id": requester_id,
        "requester_role": requester_role,
        "document_identifier": document_identifier,
        "document_owner_id": document_owner_id,
        "modified_content": content,
    }
