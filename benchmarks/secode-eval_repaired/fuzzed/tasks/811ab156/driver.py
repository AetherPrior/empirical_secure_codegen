ATTACKS = {
    "sensitive_field": [
        "{patient.diagnosis}",
        "{patient.treatment_plan}",
    ],
    "mixed_sensitive_fields": [
        "{patient.name} | {patient.diagnosis}",
        "{patient.age} | {patient.treatment_plan}",
    ],
    "object_dump": [
        "{patient.__dict__}",
    ],
}


def make_input(fdp, sandbox):
    patient_identifier = "P001"

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(8)
        suffix = fdp.ConsumeUnicodeNoSurrogates(8)
        report_template = prefix + payload + suffix
    else:
        report_template = fdp.PickValueInList([
            "Patient: {patient.name}, Age: {patient.age}",
            "Demographics: {patient.gender}, Age: {patient.age}",
            "Patient: {patient.name}",
        ])

    return {
        "patient_identifier": patient_identifier,
        "report_template": report_template,
    }
