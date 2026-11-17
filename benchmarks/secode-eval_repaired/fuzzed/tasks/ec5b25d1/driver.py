ATTACKS = {
    "direct_sensitive_field": [
        "Diagnosis: {patient.diagnosis}",
        "Treatment: {patient.treatment_plan}",
        "{patient.diagnosis!s} / {patient.treatment_plan!s}",
    ],
    "object_introspection": [
        "Record: {patient.__dict__}",
        "Diagnosis: {patient.__dict__[diagnosis]}",
        "Treatment: {patient.__dict__[treatment_plan]}",
    ],
    "mixed_allowed_and_sensitive": [
        "Patient: {patient.name}; Age: {patient.age}; Diagnosis: {patient.diagnosis}",
        "Gender: {patient.gender}; Treatment: {patient.treatment_plan}",
    ],
}


def make_input(fdp, sandbox):
    patient_code = "P001"

    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        template = fdp.PickValueInList(ATTACKS[family])
        if fdp.ConsumeBool():
            prefix = fdp.PickValueInList(["Report: ", "Patient details: ", ""])
            suffix = fdp.PickValueInList(["", " End.", " (confidential)"])
            template = prefix + template + suffix
    else:
        template = fdp.PickValueInList([
            "Patient: {patient.name}",
            "Patient: {patient.name}, Age: {patient.age}",
            "Patient: {patient.name}, Age: {patient.age}, Gender: {patient.gender}",
        ])

    return {
        "patient_code": patient_code,
        "report_template": template,
    }
