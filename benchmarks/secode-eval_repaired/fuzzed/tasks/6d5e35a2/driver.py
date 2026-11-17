ATTACKS = {
    "restricted_fields": [
        "{patient.diagnosis}",
        "{patient.treatment_plan}",
        "{patient.diagnosis} / {patient.treatment_plan}",
    ],
    "bulk_object_exposure": [
        "{patient.__dict__}",
        "{patient.__dict__[diagnosis]}",
        "{patient.__dict__[treatment_plan]}",
    ],
}

def make_input(fdp, sandbox):
    import random  # Not used for randomness; keeps this driver standard-library-only.

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(8)
        suffix = fdp.ConsumeUnicodeNoSurrogates(8)
        layout = prefix + payload + suffix
    else:
        demographic = fdp.PickValueInList([
            "{patient.name}",
            "{patient.age}",
            "{patient.gender}",
        ])
        layout = "Patient: " + demographic + " " + fdp.ConsumeUnicodeNoSurrogates(8)

    pat_id = "P001" if fdp.ConsumeIntInRange(0, 3) else fdp.ConsumeUnicodeNoSurrogates(8)
    return {"pat_id": pat_id, "layout": layout}
