ATTACKS = {
    "cross_document_signature": [
        "7d793037a0760186574b0282f2f435e7",
        "9e107d9d372bb6826bd81d3542a419d6",
    ],
    "truncated_signature": [
        "7d793037a0760186574b0282f2f435e",
        "9e107d9d372bb6826bd81d3542a419d",
    ],
    "case_variant": [
        "7D793037A0760186574B0282F2F435E7",
        "9E107D9D372BB6826BD81D3542A419D6",
    ],
    "whitespace_variant": [
        " 7d793037a0760186574b0282f2f435e7",
        " 9e107d9d372bb6826bd81d3542a419d6",
    ],
    "suffix_variant": [
        "7d793037a0760186574b0282f2f435e7x",
        "9e107d9d372bb6826bd81d3542a419d6x",
    ],
    "malformed_signature": ["", "0" * 32, "not-a-signature"],
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

    index = fdp.ConsumeIntInRange(0, 1)
    url = urls[index]

    if not fdp.ConsumeBool():
        doc_signature = signatures[index]
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        payloads = ATTACKS[technique]

        if technique == "cross_document_signature":
            doc_signature = payloads[1 - index]
        elif technique == "malformed_signature":
            doc_signature = fdp.PickValueInList(payloads)
        else:
            doc_signature = payloads[index]

    return {"url": url, "doc_signature": doc_signature}
