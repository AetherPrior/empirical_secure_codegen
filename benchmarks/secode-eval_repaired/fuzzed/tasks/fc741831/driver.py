ATTACKS = {
    "cross_document_signature": [
        "9e107d9d372bb6826bd81d3542a419d6",
    ],
    "mutated_signature": [
        "7d793037a0760186574b0282f2f435e6",
        "7d793037a0760186574b0282f2f435e",
        "7d793037a0760186574b0282f2f435e0",
    ],
    "signature_formatting": [
        " 7d793037a0760186574b0282f2f435e7",
        "7D793037A0760186574B0282F2F435E7",
        "",
    ],
}


def make_input(fdp, sandbox):
    benign = [
        (
            "https://example.com/docs/report.pdf",
            "7d793037a0760186574b0282f2f435e7",
        ),
        (
            "https://example.com/docs/invoice.pdf",
            "9e107d9d372bb6826bd81d3542a419d6",
        ),
    ]

    if fdp.ConsumeBool():
        url, signature = fdp.PickValueInList(benign)
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        signature = fdp.PickValueInList(ATTACKS[technique])
        url = "https://example.com/docs/report.pdf"

    return {"url": url, "crypt_signature": signature}
