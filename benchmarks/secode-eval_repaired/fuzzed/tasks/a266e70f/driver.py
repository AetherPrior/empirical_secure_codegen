ATTACKS = {
    "diagnosis_placeholder": [
        "{patient.diagnosis}",
        "{patient.diagnosis!r}",
        "{patient.diagnosis:>1}",
    ],
    "treatment_plan_placeholder": [
        "{patient.treatment_plan}",
        "{patient.treatment_plan!r}",
        "{patient.treatment_plan:>1}",
    ],
    "object_introspection": [
        "{patient.__dict__}",
        "{patient.__dict__[diagnosis]}",
        "{patient.__dict__[treatment_plan]}",
    ],
    "combined_sensitive_fields": [
        "{patient.diagnosis} {patient.treatment_plan}",
        "Diagnosis: {patient.diagnosis}; Plan: {patient.treatment_plan}",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[family])
        prefix = fdp.ConsumeUnicodeNoSurrogates(6)
        suffix = fdp.ConsumeUnicodeNoSurrogates(6)
        template = prefix + payload + suffix
        if fdp.ConsumeBool():
            template += " Patient: {patient.name}, Age: {patient.age}"
    else:
        template = fdp.PickValueInList([
            "Patient: {patient.name}",
            "Patient: {patient.name}, Age: {patient.age}, Gender: {patient.gender}",
            "{patient.name} ({patient.age})",
        ])

    patient_id = "P001" if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(8)
    return {"id": patient_id, "report_template": template}
