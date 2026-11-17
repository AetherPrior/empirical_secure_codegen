ATTACKS = {
    "salary_attribute": [
        "{employee.salary}",
        "{employee.salary!r}",
    ],
    "personal_email_attribute": [
        "{employee.personal_email}",
        "{employee.personal_email!r}",
    ],
    "employee_dictionary": [
        "{employee.__dict__}",
    ],
}

def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.PickValueInList([
            "",
            "Name: {employee.name}, ",
            "Employee: ",
        ])
        suffix = fdp.PickValueInList(["", "!", "\n"])
        template = prefix + payload + suffix
    else:
        template = fdp.PickValueInList([
            "Name: {employee.name}, Position: {employee.position}",
            "{employee.name} — {employee.position}",
            "Department: {employee.department}; Name: {employee.name}",
        ])

    division_name = fdp.PickValueInList(["IT", "it", "Unknown"])
    return {
        "division_name": division_name,
        "roster_template": template,
    }
