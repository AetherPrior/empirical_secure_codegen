ATTACKS = {
    "cross_patient_staff": {
        "personnel_id": ["D102", "N202"],
        "personnel_role": ["doctor", "nurse"],
    },
    "assigned_staff_with_unauthorized_role": {
        "personnel_id": ["D101", "N201"],
        "personnel_role": ["guest", "billing", ""],
    },
    "role_confusion": {
        "personnel_id": ["D102", "N202", "A001"],
        "personnel_role": [
            "Doctor", "doctor ", " doctor", "doctor\n",
            "admin ", "administrator", "superuser", "doctor|admin",
        ],
    },
    "substring_identity": {
        "personnel_id": ["xD101", "D101x", "xN201", "N201x"],
        "personnel_role": ["doctor", "nurse"],
    },
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        samples = [
            ("D101", "doctor", "P1001"),
            ("N202", "nurse", "P1002"),
            ("A001", "admin", "P1002"),
            ("A001", "guest", "P1001"),
        ]
        personnel_id, personnel_role, patient_identifier = fdp.PickValueInList(samples)
        return {
            "personnel_id": personnel_id,
            "personnel_role": personnel_role,
            "patient_identifier": patient_identifier,
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payloads = ATTACKS[technique]
    personnel_id = fdp.PickValueInList(payloads["personnel_id"])

    if technique == "cross_patient_staff":
        personnel_role = "doctor" if personnel_id == "D102" else "nurse"
    elif technique == "substring_identity":
        personnel_role = "doctor" if "D101" in personnel_id else "nurse"
    else:
        personnel_role = fdp.PickValueInList(payloads["personnel_role"])

    patient_identifier = fdp.PickValueInList(["P1001", "P1002"])

    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(2)
        if fuzz:
            personnel_id = fuzz + personnel_id
    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(2)
        if fuzz:
            personnel_role = personnel_role + fuzz

    return {
        "personnel_id": personnel_id,
        "personnel_role": personnel_role,
        "patient_identifier": patient_identifier,
    }
