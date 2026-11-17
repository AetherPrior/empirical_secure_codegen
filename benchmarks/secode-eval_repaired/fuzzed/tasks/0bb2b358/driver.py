ATTACKS = {
    "diagnosis_placeholder": [
        "{patient.diagnosis}",
        "Diagnosis: {patient.diagnosis}",
        "{patient.diagnosis!s}",
    ],
    "treatment_placeholder": [
        "{patient.treatment_plan}",
        "Treatment: {patient.treatment_plan}",
        "{patient.treatment_plan!s}",
    ],
    "object_attribute_exposure": [
        "{patient.__dict__}",
        "{patient.__dict__[diagnosis]}",
        "{patient.__dict__[treatment_plan]}",
    ],
    "mixed_demographic_and_sensitive": [
        "{patient.name} — {patient.diagnosis}",
        "{patient.age}, {patient.gender}, {patient.treatment_plan}",
    ],
}

def make_input(fdp, sandbox):
    patient_id = "P001"

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        template = fdp.PickValueInList(ATTACKS[technique])
        if fdp.ConsumeBool():
            prefix = fdp.ConsumeUnicodeNoSurrogates(8)
            template = prefix + template
        if fdp.ConsumeBool():
            suffix = fdp.ConsumeUnicodeNoSurrogates(8)
            template += suffix
    else:
        template = fdp.PickValueInList([
            "Patient: {patient.name}",
            "Age: {patient.age}; Gender: {patient.gender}",
            "{patient.name}, age {patient.age}, {patient.gender}",
        ])

    return {"patient_id": patient_id, "template": template}
