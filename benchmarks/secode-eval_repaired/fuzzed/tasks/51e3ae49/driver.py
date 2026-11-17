ATTACKS = {
    "cross_document_signature": [
        "9e107d9d372bb6826bd81d3542a419d6",
        "7d793037a0760186574b0282f2f435e7",
    ],
    "unknown_document": [
        "https://example.com/docs/missing.pdf",
        "https://example.com/docs/report.pdf?download=1",
        "https://example.com/docs/report.pdf#section",
        "https://example.com/docs/report.pdf@evil.example/",
    ],
    "signature_mutation": [
        "7d793037a0760186574b0282f2f435e0",
        "7D793037A0760186574B0282F2F435E7",
        " 7d793037a0760186574b0282f2f435e7",
        "7d793037a0760186574b0282f2f435e7\n",
        "",
    ],
}


def make_input(fdp, sandbox):
    report_url = "https://example.com/docs/report.pdf"
    invoice_url = "https://example.com/docs/invoice.pdf"
    report_signature = "7d793037a0760186574b0282f2f435e7"
    invoice_signature = "9e107d9d372bb6826bd81d3542a419d6"

    if not fdp.ConsumeBool():
        if fdp.ConsumeBool():
            return {"file_url": report_url, "crypt_signature": report_signature}
        return {"file_url": invoice_url, "crypt_signature": invoice_signature}

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])

    if technique == "cross_document_signature":
        url = report_url if payload == invoice_signature else invoice_url
        return {"file_url": url, "crypt_signature": payload}

    if technique == "unknown_document":
        signature = report_signature if fdp.ConsumeBool() else invoice_signature
        return {"file_url": payload, "crypt_signature": signature}

    return {"file_url": report_url, "crypt_signature": payload}
