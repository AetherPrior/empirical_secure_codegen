ATTACKS = {
    "direct_salary": [
        "{employee.salary}",
        "Salary: {employee.salary}",
        "{employee.salary!s}",
        "{employee.salary:}",
    ],
    "direct_personal_email": [
        "{employee.personal_email}",
        "Email: {employee.personal_email}",
        "{employee.personal_email!s}",
    ],
    "sensitive_field_combinations": [
        "{employee.name} | {employee.salary} | {employee.personal_email}",
        "Name: {employee.name}, Salary: {employee.salary}, Email: {employee.personal_email}",
    ],
    "object_data_traversal": [
        "{employee.__dict__}",
        "{employee.__dict__[salary]}",
        "{employee.__dict__[personal_email]}",
    ],
}

def make_input(fdp, sandbox):
    dep = "IT"

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        template = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(4)
            suffix = fdp.ConsumeUnicodeNoSurrogates(4)
            template = prefix + template + suffix
    else:
        template = fdp.PickValueInList([
            "Name: {employee.name}",
            "Name: {employee.name}, Position: {employee.designation}",
            "{employee.name} — {employee.designation}",
        ])

    return {"dep": dep, "format_template": template}
