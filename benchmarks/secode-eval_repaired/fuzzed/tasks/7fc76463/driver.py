ATTACKS = {
    "direct_sensitive_field": [
        "{patient.diagnosis}",
        "{patient.treatment_plan}",
    ],
    "format_conversion": [
        "{patient.diagnosis!r}",
        "{patient.treatment_plan!s}",
    ],
    "object_introspection": [
        "{patient.__dict__}",
        "{patient.__dict__[diagnosis]}",
        "{patient.__dict__[treatment_plan]}",
    ],
}


def make_input(fdp, sandbox):
    benign_templates = [
        "Patient: {patient.name}, Age: {patient.age}",
        "Name: {patient.name}; Gender: {patient.gender}",
        "{patient.name} ({patient.age}), {patient.gender}",
    ]

    identifier = "P001"
    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.ConsumeUnicodeNoSurrogates(6)
        suffix = fdp.ConsumeUnicodeNoSurrogates(6)
        benign = fdp.PickValueInList(benign_templates)
        if fdp.ConsumeBool():
            template = prefix + benign + " " + payload + suffix
        else:
            template = prefix + payload + suffix
    else:
        template = fdp.PickValueInList(benign_templates)

    return {"identifier": identifier, "report_template": template}
