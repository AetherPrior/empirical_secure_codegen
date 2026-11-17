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
    "truncated_signature": [
        "7d793037a0760186574b0282f2f435e",
        "9e107d9d372bb6826bd81d3542a419",
    ],
    "altered_signature": [
        "7d793037a0760186574b0282f2f435e0",
        "9e107d9d372bb6826bd81d3542a419e",
        "00000000000000000000000000000000",
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
    file_url, correct_signature = fdp.PickValueInList(documents)

    if fdp.ConsumeBool():
        sign = correct_signature
    else:
        technique = fdp.PickValueInList(sorted(ATTACKS))
        sign = fdp.PickValueInList(ATTACKS[technique])

    return {"file_url": file_url, "sign": sign}
