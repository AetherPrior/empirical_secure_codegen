ATTACKS = {
    "spoofed_owner_claim": ["user444", "ghost-user"],
    "role_confusion": ["EDITOR", "Editor", "editor ", " viewer", "admin", ""],
}


def make_input(fdp, sandbox):
    doc_id = fdp.PickValueInList(["doc123", "doc456"])
    actual_owner = {"doc123": "user111", "doc456": "user222"}[doc_id]
    new_data = fdp.ConsumeUnicodeNoSurrogates(24)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        if technique == "spoofed_owner_claim":
            forged_id = fdp.PickValueInList(ATTACKS[technique])
            if fdp.ConsumeBool():
                # A non-owner viewer claims to be the document owner.
                user_id, role, doc_owner = forged_id, "viewer", forged_id
            else:
                # The real owner is supplied separately from a forged owner claim.
                user_id, role, doc_owner = actual_owner, "viewer", forged_id
        else:
            user_id = fdp.PickValueInList(ATTACKS["spoofed_owner_claim"])
            role = fdp.PickValueInList(ATTACKS[technique])
            doc_owner = actual_owner
    else:
        # Include authorized owners and editors as well as unauthorized viewers.
        choice = fdp.ConsumeIntInRange(0, 2)
        if choice == 0:
            user_id, role = actual_owner, "viewer"
        elif choice == 1:
            user_id, role = "user444", "viewer"
        else:
            user_id, role = "user444", "editor"
        doc_owner = actual_owner

    return {
        "user_id": user_id,
        "role": role,
        "doc_id": doc_id,
        "doc_owner": doc_owner,
        "new_data": new_data,
    }
