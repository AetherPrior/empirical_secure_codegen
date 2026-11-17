ATTACKS = {
    "unassigned_staff": ["D102", "N202"],
    "unauthorized_role": ["receptionist", "billing", "guest"],
    "role_case_confusion": ["Doctor", "Nurse", "ADMIN"],
    "role_prefix_confusion": ["administrator", "doctor/admin", "nurse "],
    "spoofed_staff_id": ["D101 ", " D101", "N201x"],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        samples = [
            {"staff_num": "D101", "role": "doctor", "patient_ref": "P1001"},
            {"staff_num": "N201", "role": "nurse", "patient_ref": "P1001"},
            {"staff_num": "D102", "role": "doctor", "patient_ref": "P1002"},
            {"staff_num": "N202", "role": "nurse", "patient_ref": "P1002"},
            {"staff_num": "A001", "role": "admin", "patient_ref": "P1002"},
        ]
        return dict(fdp.PickValueInList(samples))

    family = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[family])
    patient_ref = "P1001"

    if family == "unassigned_staff":
        role = "doctor" if payload.startswith("D") else "nurse"
        staff_num = payload
    elif family == "unauthorized_role":
        role = payload
        staff_num = "D101"
    elif family == "role_case_confusion":
        role = payload
        staff_num = "D101"
    elif family == "role_prefix_confusion":
        role = payload
        staff_num = "D101"
    else:
        staff_num = payload
        role = "nurse" if "N" in payload else "doctor"

    return {
        "staff_num": staff_num,
        "role": role,
        "patient_ref": patient_ref,
    }
