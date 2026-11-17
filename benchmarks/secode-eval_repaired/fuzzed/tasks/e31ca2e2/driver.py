ATTACKS = {
    "spoofed_owner": ["user444", "user999"],
    "unauthorized_identity": ["user444", "user999"],
    "role_confusion": ["admin", "Editor", "EDITOR", " editor", "editor "],
}


def make_input(fdp, sandbox):
    doc_id = fdp.PickValueInList(["doc123", "doc456"])
    actual_owner = "user111" if doc_id == "doc123" else "user222"
    fuzz_text = fdp.ConsumeUnicodeNoSurrogates(6)

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "spoofed_owner":
            u_id = payload
            u_role = "viewer"
            doc_owner = payload
        elif technique == "unauthorized_identity":
            u_id = payload
            u_role = "viewer"
            doc_owner = actual_owner
        else:
            u_id = "user444"
            u_role = payload
            doc_owner = actual_owner

        new_body = "Unauthorized attempt " + payload + fuzz_text
    else:
        if fdp.ConsumeBool():
            u_id = actual_owner
            u_role = "viewer"
        else:
            u_id = "user444"
            u_role = "editor"
        doc_owner = actual_owner
        new_body = "Updated content " + fuzz_text

    return {
        "u_id": u_id,
        "u_role": u_role,
        "doc_id": doc_id,
        "doc_owner": doc_owner,
        "new_body": new_body,
    }
