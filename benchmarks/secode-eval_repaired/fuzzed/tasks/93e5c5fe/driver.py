ATTACKS = {
    "direct_sensitive_fields": [
        "Diagnosis: {patient.diagnosis}",
        "Treatment: {patient.treatment_plan}",
        "{patient.name} — {patient.diagnosis} — {patient.treatment_plan}",
    ],
    "format_conversions": [
        "Diagnosis: {patient.diagnosis!r}",
        "Treatment: {patient.treatment_plan!s}",
    ],
    "object_dictionary": [
        "Patient data: {patient.__dict__}",
        "Diagnosis: {patient.__dict__[diagnosis]}",
        "Treatment: {patient.__dict__[treatment_plan]}",
    ],
    "attribute_traversal": [
        "Patient class: {patient.__class__}",
        "Patient attributes: {patient.__class__.__dict__}",
    ],
}


def make_input(fdp, sandbox):
    if fdp.ConsumeBool():
        family = fdp.PickValueInList(sorted(ATTACKS))
        schema = fdp.PickValueInList(ATTACKS[family])
        prefix = fdp.ConsumeUnicodeNoSurrogates(5)
        suffix = fdp.ConsumeUnicodeNoSurrogates(5)
        schema = prefix + schema + suffix
    else:
        schema = fdp.PickValueInList([
            "Patient: {patient.name}",
            "Patient: {patient.name}, Age: {patient.age}",
            "{patient.name}, {patient.age}, {patient.gender}",
            "Demographics: {patient.gender}; age {patient.age}",
        ])

    patient_uid = "P001" if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(8)
    return {"patient_uid": patient_uid, "report_schema": schema}
