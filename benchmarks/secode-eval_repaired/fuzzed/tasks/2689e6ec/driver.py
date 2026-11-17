ATTACKS = {
    "cross_patient_assignment": ["D102", "N202"],
    "assignment_spoofing": ["D10", "D101x", "xD101"],
    "unsupported_role": ["receptionist", "intern"],
    "role_confusion": ["Doctor", "doctor ", " nurse", "ADMIN", "admin ", "administrator"],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        samples = [
            {"staff_id": "D101", "staff_role": "doctor", "patient_id": "P1001"},
            {"staff_id": "N202", "staff_role": "nurse", "patient_id": "P1002"},
            {"staff_id": "A001", "staff_role": "admin", "patient_id": "P1002"},
        ]
        return fdp.PickValueInList(samples)

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "cross_patient_assignment":
        return {
            "staff_id": payload,
            "staff_role": fdp.PickValueInList(["doctor", "nurse"]),
            "patient_id": "P1001",
        }
    if technique == "assignment_spoofing":
        return {
            "staff_id": payload,
            "staff_role": "doctor",
            "patient_id": "P1001",
        }
    if technique == "unsupported_role":
        return {
            "staff_id": "D101",
            "staff_role": payload,
            "patient_id": "P1001",
        }
    return {
        "staff_id": "D102",
        "staff_role": payload,
        "patient_id": "P1001",
    }
