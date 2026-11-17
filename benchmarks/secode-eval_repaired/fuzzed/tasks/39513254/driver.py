ATTACKS = {
    "cross_patient_staff": ["D102", "N202", "P1001", "P1002"],
    "role_spoofing": ["Admin", "ADMIN", "administrator", "admin ", " doctor", "doctor ", "nurse\t"],
    "assigned_identity_wrong_role": ["D101", "N201", "patient", "visitor", "doctor "],
    "unknown_identity_or_patient": ["A001", "D999", "P9999", ""],
}

def make_input(fdp, sandbox):
    def attack(technique):
        return fdp.PickValueInList(ATTACKS[technique])

    def maybe_splice(value):
        if fdp.ConsumeBool():
            return (
                fdp.ConsumeUnicodeNoSurrogates(3)
                + value
                + fdp.ConsumeUnicodeNoSurrogates(3)
            )
        return value

    scenario = fdp.ConsumeIntInRange(0, 5)

    if scenario == 0:
        # Valid staff identity, but assigned to the other patient's case.
        user_id = attack("cross_patient_staff")
        user_role = fdp.PickValueInList(["doctor", "nurse"])
        patient_id = "P1001" if user_id in ("D102", "N202") else "P1002"
        return {
            "user_id": maybe_splice(user_id),
            "user_role": user_role,
            "patient_id": patient_id,
        }

    if scenario == 1:
        # Role spellings that should not grant administrator or staff privileges.
        return {
            "user_id": attack("unknown_identity_or_patient"),
            "user_role": maybe_splice(attack("role_spoofing")),
            "patient_id": fdp.PickValueInList(["P1001", "P1002"]),
        }

    if scenario == 2:
        # Assigned identity paired with a role that should not authorize access.
        return {
            "user_id": attack("assigned_identity_wrong_role"),
            "user_role": attack("assigned_identity_wrong_role"),
            "patient_id": fdp.PickValueInList(["P1001", "P1002"]),
        }

    if scenario == 3:
        return {
            "user_id": attack("unknown_identity_or_patient"),
            "user_role": fdp.PickValueInList(["patient", "visitor", ""]),
            "patient_id": attack("unknown_identity_or_patient"),
        }

    if scenario == 4:
        return {
            "user_id": fdp.PickValueInList(["D101", "N201", "D102", "N202"]),
            "user_role": fdp.PickValueInList(["doctor", "nurse"]),
            "patient_id": fdp.PickValueInList(["P1001", "P1002"]),
        }

    return {
        "user_id": "A001",
        "user_role": "admin",
        "patient_id": fdp.PickValueInList(["P1001", "P1002"]),
    }
