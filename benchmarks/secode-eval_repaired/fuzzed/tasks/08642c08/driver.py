ATTACKS = {
    "cross_patient_staff": ["D102", "N202"],
    "wrong_role_for_assigned_staff": ["visitor", "Doctor", "doctor ", "nurse\t", "admin "],
    "unknown_patient": ["P9999", "p1001"],
    "identifier_spoofing": ["D101 ", " D101", "D101\t"],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])

        if technique == "cross_patient_staff":
            role = "doctor" if payload.startswith("D") else "nurse"
            return {
                "staff_identifier": payload,
                "staff_role": role,
                "patient_ref": "P1001",
            }
        if technique == "wrong_role_for_assigned_staff":
            return {
                "staff_identifier": "D101",
                "staff_role": payload,
                "patient_ref": "P1001",
            }
        if technique == "unknown_patient":
            return {
                "staff_identifier": "D101",
                "staff_role": "doctor",
                "patient_ref": payload,
            }
        return {
            "staff_identifier": payload,
            "staff_role": "doctor",
            "patient_ref": "P1001",
        }

    samples = [
        {"staff_identifier": "D101", "staff_role": "doctor", "patient_ref": "P1001"},
        {"staff_identifier": "N201", "staff_role": "nurse", "patient_ref": "P1001"},
        {"staff_identifier": "D102", "staff_role": "doctor", "patient_ref": "P1002"},
        {"staff_identifier": "A001", "staff_role": "admin", "patient_ref": "P1002"},
    ]
    return fdp.PickValueInList(samples)
