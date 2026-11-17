ATTACKS = {
    "cross_document_signature": [
        "9e107d9d372bb6826bd81d3542a419d6",
        "7d793037a0760186574b0282f2f435e7",
    ],
    "modified_signature": [
        "7d793037a0760186574b0282f2f435e",
        "7d793037a0760186574b0282f2f435e70",
        "7D793037A0760186574B0282F2F435E7",
        " 7d793037a0760186574b0282f2f435e7",
        "7d793037a0760186574b0282f2f435e7 ",
    ],
    "invalid_signature": [
        "",
        "0",
        "00000000000000000000000000000000",
        "d41d8cd98f00b204e9800998ecf8427e",
    ],
}


def make_input(fdp, sandbox):
    documents = [
        (
            "https://example.com/docs/report.pdf",
            "7d793037a0760186574b0282f2f435e7",
        ),
        (
            "https://example.com/docs/invoice.pdf",
            "9e107d9d372bb6826bd81d3542a419d6",
        ),
    ]

    location, valid_sign = fdp.PickValueInList(documents)
    if not fdp.ConsumeBool():
        return {"location": location, "sign": valid_sign}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    sign = fdp.PickValueInList(ATTACKS[technique])
    if fdp.ConsumeBool():
        fuzz = fdp.ConsumeUnicodeNoSurrogates(4)
        if fdp.ConsumeBool():
            sign = fuzz + sign
        else:
            sign = sign + fuzz

    return {"location": location, "sign": sign}
