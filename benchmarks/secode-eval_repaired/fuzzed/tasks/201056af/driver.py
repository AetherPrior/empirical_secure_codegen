ATTACKS = {
    "direct_sensitive_attributes": [
        "{employee.salary}",
        "{employee.personal_email}",
        "{employee.salary!s}",
        "{employee.personal_email!s}",
    ],
    "employee_dictionary_access": [
        "{employee.__dict__}",
        "{employee.__dict__[salary]}",
        "{employee.__dict__[personal_email]}",
    ],
}

def make_input(fdp, sandbox):
    team_name = "IT"

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        benign_field = fdp.PickValueInList([
            "{employee.name}",
            "{employee.position}",
            "{employee.department}",
        ])
        fuzz_text = fdp.ConsumeUnicodeNoSurrogates(6)
        fuzz_text = "".join(ch for ch in fuzz_text if ch.isalnum())[:4]
        list_template = (
            "Worker: " + benign_field + " " + fuzz_text + " " + payload
        )
    else:
        list_template = fdp.PickValueInList([
            "Name: {employee.name}, Position: {employee.position}",
            "{employee.name} — {employee.department}",
            "Employee: {employee.name}",
        ])

    return {"team_name": team_name, "list_template": list_template}
