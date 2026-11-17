ATTACKS = {
    "cross_patient_assignment": ["D102", "N202"],
    "unassigned_staff": ["D999", "N999"],
    "role_spoofing": ["ADMIN", "Admin", "administrator", "doctor/admin", " doctor"],
    "staff_id_formatting": [" D101", "D101 ", "D10", "D101,D102"],
    "patient_id_formatting": [" P1001", "P1001 ", "p1001", "P1003"],
}

def make_input(fdp, sandbox):
    patients = ["P1001", "P1002"]
    assigned_ids = ["D101", "N201", "D102", "N202"]
    ordinary_roles = ["doctor", "nurse"]
    benign_roles = ["doctor", "nurse", "admin"]

    case = fdp.ConsumeIntInRange(0, 7)

    if case == 0:
        # A valid staff role, but the staff member is assigned to the other patient.
        return {
            "staff_identifier": fdp.PickValueInList(ATTACKS["cross_patient_assignment"]),
            "staff_role": fdp.PickValueInList(ordinary_roles),
            "patient_ident": "P1001" if fdp.ConsumeBool() else "P1002",
        }
    if case == 1:
        # Assigned staff ID paired with a role that must not grant access.
        return {
            "staff_identifier": fdp.PickValueInList(assigned_ids),
            "staff_role": fdp.PickValueInList(ATTACKS["role_spoofing"]),
            "patient_ident": fdp.PickValueInList(patients),
        }
    if case == 2:
        return {
            "staff_identifier": fdp.PickValueInList(ATTACKS["unassigned_staff"]),
            "staff_role": fdp.PickValueInList(ordinary_roles),
            "patient_ident": fdp.PickValueInList(patients),
        }
    if case == 3:
        return {
            "staff_identifier": fdp.PickValueInList(ATTACKS["staff_id_formatting"]),
            "staff_role": fdp.PickValueInList(ordinary_roles),
            "patient_ident": fdp.PickValueInList(patients),
        }
    if case == 4:
        return {
            "staff_identifier": fdp.PickValueInList(assigned_ids),
            "staff_role": fdp.PickValueInList(ordinary_roles),
            "patient_ident": fdp.PickValueInList(ATTACKS["patient_id_formatting"]),
        }
    if case == 5:
        # Benign assigned-staff access.
        patient = fdp.PickValueInList(patients)
        staff = ["D101", "N201"] if patient == "P1001" else ["D102", "N202"]
        return {
            "staff_identifier": fdp.PickValueInList(staff),
            "staff_role": fdp.PickValueInList(ordinary_roles),
            "patient_ident": patient,
        }
    if case == 6:
        # Benign administrator access, including access across assignments.
        return {
            "staff_identifier": fdp.ConsumeUnicodeNoSurrogates(8),
            "staff_role": "admin",
            "patient_ident": fdp.PickValueInList(patients),
        }

    # Fuzzed values exercise unexpected roles and identifiers.
    return {
        "staff_identifier": fdp.ConsumeUnicodeNoSurrogates(8),
        "staff_role": fdp.PickValueInList(benign_roles + ATTACKS["role_spoofing"]),
        "patient_ident": fdp.PickValueInList(patients + ATTACKS["patient_id_formatting"]),
    }
