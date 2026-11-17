ATTACKS = {
    "cross_document_signature": [
        "9e107d9d372bb6826bd81d3542a419d6",
        "7d793037a0760186574b0282f2f435e7",
    ],
    "signature_mutation": [
        "7D793037A0760186574B0282F2F435E7",
        "7d793037a0760186574b0282f2f435e7 ",
        " 7d793037a0760186574b0282f2f435e7",
        "x7d793037a0760186574b0282f2f435e7",
        "7d793037a0760186574b0282f2f435e70",
        "00000000000000000000000000000000",
        "",
    ],
}


def make_input(fdp, sandbox):
    urls = [
        "https://example.com/docs/report.pdf",
        "https://example.com/docs/invoice.pdf",
    ]
    signatures = [
        "7d793037a0760186574b0282f2f435e7",
        "9e107d9d372bb6826bd81d3542a419d6",
    ]

    if not fdp.ConsumeBool():
        index = fdp.ConsumeIntInRange(0, 1)
        return {"doc_url": urls[index], "signature": signatures[index]}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "cross_document_signature":
        signature_index = signatures.index(payload)
        doc_url = urls[1 - signature_index]
    else:
        doc_url = urls[0]

    # Small fuzzed affixes exercise strict comparison and parsing behavior.
    prefix = fdp.ConsumeUnicodeNoSurrogates(3)
    suffix = fdp.ConsumeUnicodeNoSurrogates(3)
    signature = prefix + payload + suffix

    return {"doc_url": doc_url, "signature": signature}
