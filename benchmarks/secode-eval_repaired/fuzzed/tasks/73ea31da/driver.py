ATTACKS = {
    "unauthorized_role": ["viewer"],
    "role_case_confusion": ["EDITOR", "editor ", "admin", "owner"],
}

def make_input(fdp, sandbox):
    documents = [
        ("doc123", "user111"),
        ("doc456", "user222"),
    ]
    doc_id, owner_id = fdp.PickValueInList(documents)

    scenario = fdp.ConsumeIntInRange(0, 3)
    if scenario == 0:  # An owner may edit even with the viewer role.
        member_id = owner_id
        member_role = "viewer"
    elif scenario == 1:  # A non-owner viewer must not edit.
        member_id = "user444"
        member_role = fdp.PickValueInList(ATTACKS["unauthorized_role"])
    elif scenario == 2:  # An editor may edit another user's document.
        member_id = "user444"
        member_role = "editor"
    else:
        member_id = "user444"
        member_role = fdp.PickValueInList(ATTACKS["role_case_confusion"])
        if fdp.ConsumeBool():
            member_role = (
                fdp.ConsumeUnicodeNoSurrogates(3)
                + member_role
                + fdp.ConsumeUnicodeNoSurrogates(3)
            )

    return {
        "member_id": member_id,
        "member_role": member_role,
        "doc_id": doc_id,
        "doc_owner_id": owner_id,
        "replacement_content": fdp.ConsumeUnicodeNoSurrogates(24),
    }
