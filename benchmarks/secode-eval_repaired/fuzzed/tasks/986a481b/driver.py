ATTACKS = {
    "unauthorized_identity": ["user444", "user999"],
    "creator_spoof": ["user444", "user999"],
    "role_case_confusion": ["Editor", "EDITOR"],
    "role_whitespace": ["editor ", " editor", "editor\t"],
    "role_composite": ["viewer,editor", "viewer|editor", "not-editor"],
    "identity_variants": ["user111 ", " user111", "USER111"],
}


def make_input(fdp, sandbox):
    docs = [("doc123", "user111"), ("doc456", "user222")]
    doc_ref, actual_creator = fdp.PickValueInList(docs)
    mode = fdp.ConsumeIntInRange(0, 7)

    owner = actual_creator
    doc_creator = actual_creator
    editor_role = "viewer"

    def attack(technique):
        return fdp.PickValueInList(ATTACKS[technique])

    if mode == 1:
        owner = attack("unauthorized_identity")
    elif mode == 2:
        owner = attack("creator_spoof")
        doc_creator = owner
    elif mode == 3:
        owner = attack("unauthorized_identity")
        editor_role = attack(fdp.PickValueInList([
            "role_case_confusion", "role_whitespace", "role_composite"
        ]))
    elif mode == 4:
        doc_creator = attack("identity_variants")
    elif mode == 5:
        owner = attack("unauthorized_identity")
        editor_role = "editor"
    elif mode == 6:
        other_creator = "user222" if actual_creator == "user111" else "user111"
        owner = other_creator
        doc_creator = other_creator
    elif mode == 7:
        owner = attack("unauthorized_identity")
        editor_role = attack("role_whitespace")

    if mode in (1, 3, 7) and fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(3)
        if fdp.ConsumeBool():
            owner = fuzz + owner
        else:
            owner = owner + fuzz

    revised_content = (
        "Updated content"
        if not fdp.ConsumeBool()
        else fdp.ConsumeUnicodeNoSurrogates(24)
    )

    return {
        "owner": owner,
        "editor_role": editor_role,
        "doc_ref": doc_ref,
        "doc_creator": doc_creator,
        "revised_content": revised_content,
    }
