ATTACKS = {
    "cross_document_signature_replay": [
        "7d793037a0760186574b0282f2f435e7",
        "9e107d9d372bb6826bd81d3542a419d6",
    ],
    "empty_signature": [""],
    "malformed_signature": ["invalid", "0" * 32],
    "signature_with_extra_data": [
        "7d793037a0760186574b0282f2f435e7 ",
        "9e107d9d372bb6826bd81d3542a419d6 ",
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

    if fdp.ConsumeBool():
        document_location, crypto_sign = fdp.PickValueInList(documents)
        return {
            "document_location": document_location,
            "crypto_sign": crypto_sign,
        }

    document_location, expected_signature = fdp.PickValueInList(documents)
    technique = fdp.PickValueInList(sorted(ATTACKS))

    if technique == "cross_document_signature_replay":
        crypto_sign = (
            ATTACKS[technique][1]
            if expected_signature == ATTACKS[technique][0]
            else ATTACKS[technique][0]
        )
    elif technique == "signature_with_extra_data":
        crypto_sign = (
            ATTACKS[technique][0]
            if expected_signature == documents[0][1]
            else ATTACKS[technique][1]
        )
    else:
        crypto_sign = fdp.PickValueInList(ATTACKS[technique])

    return {
        "document_location": document_location,
        "crypto_sign": crypto_sign,
    }
