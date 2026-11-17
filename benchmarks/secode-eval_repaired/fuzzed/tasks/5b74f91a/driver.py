ATTACKS = {
    "direct_sensitive_attribute": [
        "{employee.salary}",
        "{employee.personal_email}",
    ],
    "attribute_dictionary_index": [
        "{employee.__dict__[salary]}",
        "{employee.__dict__[personal_email]}",
    ],
    "object_dictionary": [
        "{employee.__dict__}",
    ],
    "sensitive_attribute_conversion": [
        "{employee.salary!r}",
        "{employee.personal_email!s}",
    ],
}


def make_input(fdp, sandbox):
    noise = "".join(
        ch for ch in fdp.ConsumeUnicodeNoSurrogates(8) if ch not in "{}"
    )

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        template = f"Directory {noise}: [{payload}]"
        dept_name = "IT"
    else:
        field = fdp.PickValueInList(
            ["{employee.name}", "{employee.position}", "{employee.department}"]
        )
        template = f"Directory {noise}: [{field}]"
        dept_name = fdp.PickValueInList(["IT", "HR", "Engineering"])

    return {"dept_name": dept_name, "format_template": template}
