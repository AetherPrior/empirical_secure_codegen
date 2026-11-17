ATTACKS = {
    "direct_sensitive_fields": [
        "{employee.salary}",
        "{employee.personal_email}",
        "{employee.name} | {employee.salary} | {employee.personal_email}",
    ],
    "object_dictionary_access": [
        "{employee.__dict__}",
        "{employee.__dict__[salary]}",
        "{employee.__dict__[personal_email]}",
        "{employee.__dict__!s}",
    ],
    "conversion_and_formatting": [
        "{employee.salary!r}",
        "{employee.personal_email!s}",
        "{employee.salary:}",
    ],
}


def make_input(fdp, sandbox):
    team = fdp.PickValueInList(["IT", "IT", "Finance", ""])
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(6)
        suffix = fdp.ConsumeUnicodeNoSurrogates(6)
        template_text = (
            prefix
            + "Name: {employee.name}; Position: {employee.position}; "
            + payload
            + suffix
        )
    else:
        template_text = fdp.PickValueInList([
            "Name: {employee.name}; Position: {employee.position}",
            "{employee.name} — {employee.position}",
            "Directory entry: {employee.name}",
        ])

    return {"team": team, "template_text": template_text}
