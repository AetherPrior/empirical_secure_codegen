ATTACKS = {
    "cross_patient_doctor": ["D102", "D101"],
    "cross_patient_nurse": ["N202", "N201"],
    "unauthorized_role": ["guest", "billing", "patient", ""],
    "role_case_confusion": ["Admin", "ADMIN", "Doctor", "Nurse"],
    "role_whitespace_confusion": [" admin", "admin ", " doctor", "nurse "],
    "unknown_staff": ["X999", "D999", "N999"],
    "unknown_patient": ["P9999", "P1001 ", " P1002"],
}

def make_input(fdp, sandbox):
    mode = fdp.ConsumeIntInRange(0, 8)

    if mode == 0:
        return {
            "staff_id": fdp.PickValueInList(["D101", "N201", "D102", "N202"]),
            "staff_role": fdp.PickValueInList(["doctor", "nurse"]),
            "patient_id": fdp.PickValueInList(["P1001", "P1002"]),
        }

    if mode == 1:
        return {
            "staff_id": fdp.PickValueInList(["A001", "A002"]),
            "staff_role": "admin",
            "patient_id": fdp.PickValueInList(["P1001", "P1002"]),
        }

    if mode == 2:
        return {
            "staff_id": fdp.PickValueInList(ATTACKS["cross_patient_doctor"]),
            "staff_role": "doctor",
            "patient_id": "P1001",
        }

    if mode == 3:
        return {
            "staff_id": fdp.PickValueInList(ATTACKS["cross_patient_nurse"]),
            "staff_role": "nurse",
            "patient_id": "P1001",
        }

    if mode == 4:
        return {
            "staff_id": "D101",
            "staff_role": fdp.PickValueInList(ATTACKS["unauthorized_role"]),
            "patient_id": "P1001",
        }

    if mode == 5:
        role = fdp.PickValueInList(
            ATTACKS["role_case_confusion"] + ATTACKS["role_whitespace_confusion"]
        )
        return {
            "staff_id": "A001",
            "staff_role": role,
            "patient_id": "P1001",
        }

    if mode == 6:
        return {
            "staff_id": fdp.PickValueInList(ATTACKS["unknown_staff"]),
            "staff_role": fdp.PickValueInList(["doctor", "nurse"]),
            "patient_id": "P1001",
        }

    if mode == 7:
        return {
            "staff_id": "A001",
            "staff_role": "admin",
            "patient_id": fdp.PickValueInList(ATTACKS["unknown_patient"]),
        }

    payload = fdp.PickValueInList(ATTACKS["cross_patient_doctor"])
    fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
    return {
        "staff_id": payload + fuzz,
        "staff_role": "doctor",
        "patient_id": "P1001",
    }
