ATTACKS = {
    "direct_diagnosis": [
        "{patient.diagnosis}",
        "{patient.diagnosis!r}",
    ],
    "direct_treatment_plan": [
        "{patient.treatment_plan}",
        "{patient.treatment_plan!s}",
    ],
    "attribute_traversal": [
        "{patient.__dict__}",
        "{patient.__dict__[diagnosis]}",
        "{patient.__dict__[treatment_plan]}",
    ],
}


def make_input(fdp, sandbox):
    patient_id = "P001"

    benign_templates = [
        "Patient: {patient.name}",
        "Patient: {patient.name}, Age: {patient.age}, Gender: {patient.gender}",
        "{patient.gender}, age {patient.age}",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        benign = fdp.PickValueInList(benign_templates)
        report_template = benign + ", Details: " + payload
        if fdp.ConsumeBool():
            noise = fdp.ConsumeUnicodeNoSurrogates(4)
            noise = "".join(c for c in noise if c.isalnum() or c in " ,.-_")
            report_template = noise + report_template
    else:
        report_template = fdp.PickValueInList(benign_templates)

    return {"patient_id": patient_id, "report_template": report_template}
