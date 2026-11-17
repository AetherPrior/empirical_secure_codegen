ATTACKS = {
    "sensitive_field_placeholders": [
        "{patient.diagnosis}",
        "{patient.treatment_plan}",
        "{patient.diagnosis} | {patient.treatment_plan}",
    ],
    "object_dictionary_access": [
        "{patient.__dict__}",
        "{patient.__dict__[diagnosis]}",
        "{patient.__dict__[treatment_plan]}",
    ],
    "private_attribute_access": [
        "{patient._Patient__dict__}",
        "{patient.__dict__[id]}",
    ],
    "conversion_and_formatting": [
        "{patient.diagnosis!s}",
        "{patient.treatment_plan!r}",
        "{patient.__dict__!s}",
    ],
}


def make_input(fdp, sandbox):
    patient_key = "P001"

    if fdp.ConsumeBool():
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payload = fdp.PickValueInList(ATTACKS[technique])
        prefix = fdp.PickValueInList(["", "Patient report: ", "Details: "])
        suffix = fdp.PickValueInList(["", " | End", "\n"])
        template_string = prefix + payload + suffix
    else:
        template_string = fdp.PickValueInList([
            "Patient: {patient.name}",
            "Patient: {patient.name}, Age: {patient.age}",
            "{patient.name}, {patient.age}, {patient.gender}",
            "Demographics: {patient.gender}",
        ])

    return {
        "patient_key": patient_key,
        "template_string": template_string,
    }
