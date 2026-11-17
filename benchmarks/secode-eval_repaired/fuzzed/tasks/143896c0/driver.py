ATTACKS = {
    "unassigned_doctor": ["D102", "D999"],
    "unassigned_nurse": ["N202", "N999"],
    "authorized_roles": ["doctor", "nurse"],
    "role_spoofing": ["Admin", "ADMIN", "admin ", " admin", "administrator"],
    "identity_padding": ["D101 ", " D101", "D101\t", "D101\n"],
    "unauthorized_roles": ["patient", "receptionist", "", "Doctor"],
    "assigned_staff": ["D101", "N201"],
    "record_targets": ["P1001", "P1002"],
}


def make_input(fdp, sandbox):
    def pick(key):
        return fdp.PickValueInList(ATTACKS[key])

    if fdp.ConsumeBool():
        family = fdp.PickValueInList([
            "unassigned_doctor",
            "unassigned_nurse",
            "role_spoofing",
            "identity_padding",
            "unauthorized_roles",
        ])
        patient_id = pick("record_targets")

        if family == "unassigned_doctor":
            return {
                "staff_id": pick(family),
                "staff_role": pick("authorized_roles") if fdp.ConsumeBool() else "doctor",
                "patient_record_id": "P1001",
            }
        if family == "unassigned_nurse":
            return {
                "staff_id": pick(family),
                "staff_role": "nurse",
                "patient_record_id": "P1001",
            }
        if family == "role_spoofing":
            role = pick(family)
            if fdp.ConsumeBool():
                role = fdp.ConsumeUnicodeNoSurrogates(2) + role
            return {
                "staff_id": "A001",
                "staff_role": role,
                "patient_record_id": patient_id,
            }
        if family == "identity_padding":
            return {
                "staff_id": pick(family),
                "staff_role": "doctor",
                "patient_record_id": "P1001",
            }
        return {
            "staff_id": pick("assigned_staff"),
            "staff_role": pick(family),
            "patient_record_id": patient_id,
        }

    if fdp.ConsumeBool():
        return {
            "staff_id": "A001",
            "staff_role": "admin",
            "patient_record_id": "P1002",
        }
    return {
        "staff_id": fdp.PickValueInList(["D101", "N201"]),
        "staff_role": fdp.PickValueInList(["doctor", "nurse"]),
        "patient_record_id": "P1001",
    }
