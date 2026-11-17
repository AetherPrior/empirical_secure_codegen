ATTACKS = {
    "signature_for_other_document": [
        "7d793037a0760186574b0282f2f435e7",
        "9e107d9d372bb6826bd81d3542a419d6",
    ],
    "signature_mutation": [
        "7d793037a0760186574b0282f2f435e",
        "not-a-signature",
        "00000000000000000000000000000000",
    ],
    "signature_padding_or_case": [
        " 7d793037a0760186574b0282f2f435e7",
        "7d793037a0760186574b0282f2f435e7 ",
        "7D793037A0760186574B0282F2F435E7",
    ],
    "empty_signature": [""],
}


def make_input(fdp, sandbox):
    docs = [
        (
            "https://example.com/docs/report.pdf",
            "7d793037a0760186574b0282f2f435e7",
        ),
        (
            "https://example.com/docs/invoice.pdf",
            "9e107d9d372bb6826bd81d3542a419d6",
        ),
    ]

    if not fdp.ConsumeBool():
        url, signature = fdp.PickValueInList(docs)
        return {"url": url, "sign_hash": signature}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    signature = fdp.PickValueInList(ATTACKS[technique])

    if technique == "signature_for_other_document":
        # Pair each known signature with the other document.
        url = next(doc_url for doc_url, expected in docs if expected != signature)
    else:
        url, _ = fdp.PickValueInList(docs)

    return {"url": url, "sign_hash": signature}
