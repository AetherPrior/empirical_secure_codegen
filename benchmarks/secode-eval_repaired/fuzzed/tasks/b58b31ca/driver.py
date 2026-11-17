ATTACKS = {
    "unassigned_staff": ["D102", "N202"],
    "identity_variants": [" D101", "D101 ", "d101", "D101,D102", "D102"],
    "role_aliases": ["Admin", "ADMIN", "administrator", "doctor ", " doctor", "doctor/admin", "superuser", "*"],
    "record_id_variants": ["p1001", "P1001 ", " P1001", "P9999", "P1001/P1002"],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        return fdp.PickValueInList([
            {"worker_id": "D101", "worker_role": "doctor", "record_id": "P1001"},
            {"worker_id": "N202", "worker_role": "nurse", "record_id": "P1002"},
            {"worker_id": "A001", "worker_role": "admin", "record_id": "P1002"},
        ])

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    if fdp.ConsumeBool():
        payload = payload + fdp.ConsumeUnicodeNoSurrogates(3)

    if technique == "unassigned_staff":
        record_id = "P1001" if payload == "D102" else "P1001"
        worker_role = "doctor" if payload == "D102" else "nurse"
        worker_id = payload
    elif technique == "identity_variants":
        worker_id = payload
        worker_role = "doctor"
        record_id = "P1001"
    elif technique == "role_aliases":
        worker_id = fdp.PickValueInList(ATTACKS["identity_variants"])
        worker_role = payload
        record_id = "P1001"
    else:
        worker_id = "D102"
        worker_role = "doctor"
        record_id = payload

    return {
        "worker_id": worker_id,
        "worker_role": worker_role,
        "record_id": record_id,
    }
