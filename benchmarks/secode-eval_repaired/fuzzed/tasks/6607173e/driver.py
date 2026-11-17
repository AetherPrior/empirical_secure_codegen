ATTACKS = {
    "salary_placeholder": [
        "Name: {employee.name}, Salary: {employee.salary}",
        "Salary: {employee.salary!s}",
        "{employee.__dict__[salary]}",
    ],
    "personal_contact_placeholder": [
        "Email: {employee.personal_email}",
        "{employee.__dict__[personal_email]}",
    ],
    "object_dictionary_exposure": [
        "{employee.__dict__}",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(4)
        suffix = fdp.ConsumeUnicodeNoSurrogates(4)
        template = prefix + payload + suffix
    else:
        template = fdp.PickValueInList([
            "Name: {employee.name}, Position: {employee.position}",
            "{employee.name} — {employee.department}",
            "Employee: {employee.name}",
        ])

    return {"department": "IT", "template": template}
