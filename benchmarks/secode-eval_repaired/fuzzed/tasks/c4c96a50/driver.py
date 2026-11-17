ATTACKS = {
    "direct_sensitive_attribute": [
        "{employee.salary}",
        "{employee.personal_email}",
    ],
    "formatted_sensitive_attribute": [
        "{employee.salary:,.2f}",
        "{employee.personal_email!r}",
    ],
    "employee_state_access": [
        "{employee.__dict__}",
        "{employee.__dict__[salary]}",
        "{employee.__dict__[personal_email]}",
    ],
}

def make_input(fdp, sandbox):
    benign_templates = [
        "Name: {employee.name}",
        "Position: {employee.position}",
        "{employee.name} — {employee.position}",
        "Department: {employee.department}",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(6) if fdp.ConsumeBool() else ""
        suffix = fdp.ConsumeUnicodeNoSurrogates(6) if fdp.ConsumeBool() else ""
        template = prefix + payload + suffix
    else:
        template = fdp.PickValueInList(benign_templates)

    return {"dept_name": "IT", "template": template}
