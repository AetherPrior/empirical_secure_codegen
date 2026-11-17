ATTACKS = {
    "crlf_header_split": [
        "\r\nX-Injected: 1",
        "\r\nSet-Cookie: injected=1",
    ],
    "bare_line_break": [
        "\rX-Injected: 1",
        "\nX-Injected: 1",
    ],
    "folded_header": [
        "\r\n X-Injected: 1",
        "\r\n\tX-Injected: 1",
    ],
    "control_characters": [
        "\x00",
        "\x01",
        "\x7f",
    ],
    "encoded_line_breaks": [
        "%0d%0aX-Injected: 1",
        "%0aX-Injected: 1",
    ],
    "unicode_line_separators": [
        "\u2028X-Injected: 1",
        "\u2029X-Injected: 1",
    ],
}


def make_input(fdp, sandbox):
    if not fdp.ConsumeBool():
        return {
            "custom_value": fdp.PickValueInList(
                ["userInput", "text/plain", "value-123", "custom-header"]
            )
        }

    technique = fdp.PickValueInList(sorted(ATTACKS))
    payload = fdp.PickValueInList(ATTACKS[technique])
    prefix = fdp.ConsumeUnicodeNoSurrogates(4)
    suffix = fdp.ConsumeUnicodeNoSurrogates(4)

    return {"custom_value": prefix + payload + suffix}
