ATTACKS = {
    "cross_patient_staff": ["D102", "N202", "D101", "N201"],
    "unassigned_identity": ["X999", "D10", "N20", "D101x", "xD101"],
    "role_case_or_whitespace": ["Doctor", "DOCTOR", " doctor", "doctor ", "Nurse", "nurse "],
    "role_escalation_or_unknown": ["admin ", "administrator", "superuser", "billing"],
    "existing_patient_code": ["P1001", "P1002"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        patient_code = fdp.PickValueInList(ATTACKS["existing_patient_code"])
        if patient_code == "P1001":
            employee_id = fdp.PickValueInList(["D102", "N202"])
        else:
            employee_id = fdp.PickValueInList(["D101", "N201"])
        employee_role = fdp.PickValueInList(["doctor", "nurse"])
    else:
        patient_code = fdp.PickValueInList(ATTACKS["existing_patient_code"])
        employee_id = fdp.PickValueInList(ATTACKS["unassigned_identity"])
        employee_role = fdp.PickValueInList(
            ATTACKS["role_case_or_whitespace"] + ATTACKS["role_escalation_or_unknown"]
        )

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(
            ["cross_patient_staff", "unassigned_identity", "role_case_or_whitespace"]
        )
        payload = fdp.PickValueInList(ATTACKS[family])
        fuzz = fdp.ConsumeUnicodeNoSurrogates(3)
        if fdp.ConsumeBool():
            employee_id = fuzz + payload
        else:
            employee_id = payload + fuzz

    if fdp.ConsumeBool():
        employee_role = fdp.PickValueInList(ATTACKS["role_case_or_whitespace"])

    if fdp.ConsumeBool():
        return {
            "employee_id": fdp.PickValueInList(["A001", "D101", "N201"]),
            "employee_role": fdp.PickValueInList(["admin", "doctor", "nurse"]),
            "patient_code": patient_code,
        }

    return {
        "employee_id": employee_id,
        "employee_role": employee_role,
        "patient_code": patient_code,
    }
