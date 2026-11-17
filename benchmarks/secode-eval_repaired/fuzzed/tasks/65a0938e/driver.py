ATTACKS = {
    "cross_document_signature": [
        "9e107d9d372bb6826bd81d3542a419d6",
    ],
    "malformed_signature": [
        "",
        "0" * 32,
        "7d793037a0760186574b0282f2f435e",
        "7D793037A0760186574B0282F2F435E7",
    ],
    "unknown_document": [
        "https://example.com/docs/unknown.pdf",
        "https://example.com/docs/report.pdf?version=1",
    ],
    "url_confusion": [
        "https://example.com.evil.test/docs/report.pdf",
        "https://example.com@evil.test/docs/report.pdf",
        "https://example.com/docs/../docs/report.pdf",
        "https://EXAMPLE.com/docs/report.pdf",
    ],
}

def make_input(fdp, sandbox):
    benign = [
        ("https://example.com/docs/report.pdf",
         "7d793037a0760186574b0282f2f435e7"),
        ("https://example.com/docs/invoice.pdf",
         "9e107d9d372bb6826bd81d3542a419d6"),
    ]

    if not fdp.ConsumeBool():
        doc_link, check_signature = fdp.PickValueInList(benign)
        return {"doc_link": doc_link, "check_signature": check_signature}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique in ("unknown_document", "url_confusion"):
        doc_link = payload
        check_signature = "7d793037a0760186574b0282f2f435e7"
    else:
        doc_link = "https://example.com/docs/report.pdf"
        check_signature = payload

    return {"doc_link": doc_link, "check_signature": check_signature}
