ATTACKS = {
    "direct_sensitive_attribute": [
        "Salary: {employee.salary}",
        "Personal email: {employee.personal_email}",
        "{employee.salary} | {employee.personal_email}",
    ],
    "attribute_dictionary": [
        "Employee data: {employee.__dict__}",
        "Salary: {employee.__dict__[salary]}",
        "Email: {employee.__dict__[personal_email]}",
    ],
    "formatted_sensitive_attribute": [
        "Salary: {employee.salary!r}",
        "Email: {employee.personal_email!s}",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        noise = fdp.ConsumeUnicodeNoSurrogates(4).replace("{", "[").replace("}", "]")
        template_str = noise + payload + noise
    else:
        template_str = fdp.PickValueInList([
            "Name: {employee.name}, Position: {employee.position}",
            "{employee.name} — {employee.position}",
            "Department: {employee.department}; Name: {employee.name}",
        ])

    return {"division": "IT", "template_str": template_str}
