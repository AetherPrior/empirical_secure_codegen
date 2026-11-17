ATTACKS = {
    "cross_document_signature": [
        "9e107d9d372bb6826bd81d3542a419d6",
        "7d793037a0760186574b0282f2f435e7",
    ],
    "empty_or_whitespace": [
        "",
        " ",
        "\t",
        "\n",
    ],
    "signature_format_mutation": [
        "7D793037A0760186574B0282F2F435E7",
        "7d793037a0760186574b0282f2f435e",
        "7d793037a0760186574b0282f2f435e7x",
        "0x7d793037a0760186574b0282f2f435e7",
    ],
    "embedded_control_or_unicode": [
        "\x007d793037a0760186574b0282f2f435e7",
        "7d793037a0760186574b0282f2f435e7\x00",
        "7d793037a0760186574b0282f2f435e\u200b",
    ],
    "url_alias_or_misdirection": [
        "https://example.com/docs/report.pdf?download=1",
        "https://example.com/docs/report.pdf#fragment",
        "https://example.com/docs/report.pdf/",
        "https://example.com/docs/./report.pdf",
        "https://example.com/docs/%72eport.pdf",
        "https://example.com@evil.test/docs/report.pdf",
        "http://example.com/docs/report.pdf",
    ],
}


def make_input(fdp, sandbox):
    report_url = "https://example.com/docs/report.pdf"
    invoice_url = "https://example.com/docs/invoice.pdf"

    if not fdp.ConsumeBool():
        if fdp.ConsumeBool():
            return {
                "resource_url": report_url,
                "crypto_signature": "7d793037a0760186574b0282f2f435e7",
            }
        return {
            "resource_url": invoice_url,
            "crypto_signature": "9e107d9d372bb6826bd81d3542a419d6",
        }

    if fdp.ConsumeBool():
        resource_url = fdp.PickValueInList([report_url, invoice_url])
    else:
        resource_url = fdp.PickValueInList(
            ATTACKS["url_alias_or_misdirection"]
        )

    technique = fdp.PickValueInList(
        [name for name in sorted(ATTACKS) if name != "url_alias_or_misdirection"]
    )
    signature = fdp.PickValueInList(ATTACKS[technique])

    if fdp.ConsumeBool():
        fuzz_text = fdp.ConsumeUnicodeNoSurrogates(3)
        if fdp.ConsumeBool():
            signature = fuzz_text + signature
        else:
            signature = signature + fuzz_text

    return {
        "resource_url": resource_url,
        "crypto_signature": signature,
    }
