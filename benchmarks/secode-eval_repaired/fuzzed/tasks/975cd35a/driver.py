ATTACKS = {
    "direct_sensitive_fields": [
        "{patient.diagnosis}",
        "{patient.treatment_plan}",
    ],
    "format_conversions": [
        "{patient.diagnosis!r}",
        "{patient.treatment_plan!s}",
    ],
    "object_dump": [
        "{patient.__dict__}",
    ],
    "attribute_traversal": [
        "{patient.__class__.__init__.__globals__[patient_records][P001].diagnosis}",
    ],
}

def make_input(fdp, sandbox):
    benign_templates = [
        "Patient: {patient.name}",
        "Patient: {patient.name}, Age: {patient.age}, Gender: {patient.gender}",
        "Name={patient.name}; age={patient.age}",
    ]

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(8)
        suffix = fdp.ConsumeUnicodeNoSurrogates(8)
        template = prefix + "Patient: {patient.name}; " + payload + suffix
    else:
        template = fdp.PickValueInList(benign_templates)

    return {
        "patient_identifier": "P001",
        "template_string": template,
    }
